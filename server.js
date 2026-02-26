const express = require('express');
const Datastore = require('@seald-io/nedb'); 
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const axios = require('axios'); // لإضافة التحقق من IP الخارجي

const app = express();

// --- 1. إعداد المسارات (متوافق مع Render) ---
const appDataPath = process.env.RENDER 
    ? path.join(process.cwd(), 'data')
    : path.join(process.env.APPDATA || process.env.LOCALAPPDATA || './', 'SalaryApp');

const dbPath = path.join(appDataPath, 'salary_data.db');
const syncLogPath = path.join(appDataPath, 'sync_log.db');
const uploadsPath = path.join(appDataPath, 'uploads');

[appDataPath, uploadsPath].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// --- 2. تهيئة قواعد البيانات ---
const db_disk = new Datastore({ filename: dbPath, autoload: true });
const syncLogDB = new Datastore({ filename: syncLogPath, autoload: true });
const sessionsDB = new Datastore({ filename: path.join(appDataPath, 'sessions.db'), autoload: true });

// --- 3. إعدادات Express ---
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// ============================================
// 🔐 إعدادات الأمان - عدّل هذه القيم
// ============================================

// IP الخارجي للمكتب (استبدله بـ IP مكتبك الفعلي)
const OFFICE_PUBLIC_IP = process.env.OFFICE_PUBLIC_IP || '203.0.113.45'; // ← غيّر هذا!

// هل تريد تفعيل قيد IP؟ (true = نعم، false = لا)
const ENABLE_IP_RESTRICTION = process.env.ENABLE_IP_RESTRICTION === 'true' || false;

// ============================================
// 🛡️ دوال الأمان
// ============================================

// الحصول على IP الخارجي للعميل
function getClientIP(req) {
    // مع مراعاة البروكسي (Render يستخدم بروكسي)
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}

// التحقق مما إذا كان IP العميل مسموحاً له
async function isAccessAllowed(req, employee) {
    const clientIP = getClientIP(req);
    
    // إذا كان قيد IP معطل، اسمح للجميع
    if (!ENABLE_IP_RESTRICTION) {
        return { allowed: true, reason: 'IP restriction disabled' };
    }
    
    // إذا كان الموظف مسموح له بالعمل عن بُعد، اسمح له من أي مكان
    if (employee.allowRemote === true) {
        return { allowed: true, reason: 'Remote access allowed for this employee' };
    }
    
    // تحقق من IP الخارجي
    if (clientIP === OFFICE_PUBLIC_IP) {
        return { allowed: true, reason: 'Office IP verified' };
    }
    
    // رفض الوصول
    return { 
        allowed: false, 
        reason: 'Access denied - Not from office IP and remote access not allowed',
        clientIP,
        officeIP: OFFICE_PUBLIC_IP
    };
}

// تسجيل محاولة دخول
function logAccessAttempt(empId, allowed, reason, ip, deviceInfo) {
    syncLogDB.insert({
        type: allowed ? 'login_success' : 'login_blocked',
        empId,
        allowed,
        reason,
        ip,
        deviceInfo,
        timestamp: new Date().toISOString()
    });
}

// دوال مساعدة أخرى
function generateDeviceFingerprint() {
    const info = [os.hostname(), os.userInfo().username, os.platform(), os.totalmem(), os.cpus()[0]?.model].join('|');
    return crypto.createHash('sha256').update(info).digest('hex').substr(0, 16);
}

function getDeviceInfo() {
    return {
        hostname: os.hostname(),
        username: os.userInfo().username,
        platform: os.platform(),
        fingerprint: generateDeviceFingerprint(),
        ip: Object.values(os.networkInterfaces()).flat().find(i => i?.family === 'IPv4' && !i.internal)?.address || 'unknown',
        timestamp: new Date().toISOString()
    };
}

function generateSessionId() {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateSecureToken(empId, deviceFingerprint) {
    return crypto.createHash('sha256')
        .update(`${empId}|${deviceFingerprint}|${process.env.SECRET_KEY || 'default_secret'}`)
        .digest('hex');
}

// ============================================
// 🔐 مسارات المصادقة والجلسات
// ============================================

// ✅ جلب قائمة الموظفين للدخول
app.get('/api/auth/employees', (req, res) => {
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).json({ error: err.message });
        const employees = (doc?.employees || []).map(e => ({
            id: e.id, 
            name: e.name, 
            empId: e.empId, 
            department: e.department,
            allowRemote: e.allowRemote || false // إظهار حالة العمل عن بُعد
        }));
        res.json({ success: true, employees });
    });
});

// ✅ تسجيل دخول الموظف (مع التحقق من IP)
app.post('/api/auth/login', async (req, res) => {
    const { empId, pin, deviceInfo } = req.body;
    const clientIP = getClientIP(req);
    
    if (!empId || !pin) {
        return res.status(400).json({ success: false, error: 'يرجى إدخال الرقم الوظيفي ورمز الدخول' });
    }

    const deviceFingerprint = deviceInfo?.fingerprint || generateDeviceFingerprint();
    
    db_disk.findOne({ type: 'main_db' }, async (err, doc) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const employee = (doc?.employees || []).find(e => e.empId === empId && e.pin == pin);
        
        if (!employee) {
            logAccessAttempt(empId, false, 'Invalid credentials', clientIP, deviceInfo);
            return res.status(401).json({ success: false, error: 'الرقم الوظيفي أو رمز الدخول غير صحيح' });
        }

        // ✅ التحقق من صلاحية الوصول (IP + allowRemote)
        const accessCheck = await isAccessAllowed(req, employee);
        
        if (!accessCheck.allowed) {
            logAccessAttempt(empId, false, accessCheck.reason, clientIP, deviceInfo);
            return res.status(403).json({ 
                success: false, 
                error: 'تسجيل الدخول غير مسموح من هذا الموقع',
                details: process.env.NODE_ENV === 'development' ? accessCheck : undefined
            });
        }

        // التحقق من جلسة نشطة
        sessionsDB.findOne({ empId: employee.id, isActive: true }, (err, activeSession) => {
            if (activeSession) {
                logAccessAttempt(empId, false, 'Already logged in', clientIP, deviceInfo);
                return res.status(400).json({ 
                    success: false, 
                    error: 'هذا الموظف مسجل دخول بالفعل',
                    device: activeSession.deviceInfo?.hostname,
                    loginTime: activeSession.loginTime
                });
            }

            const secureToken = generateSecureToken(employee.id, deviceFingerprint);
            const session = {
                sessionId: generateSessionId(),
                empId: employee.id,
                empName: employee.name,
                empCode: employee.empId,
                loginTime: new Date().toISOString(),
                deviceInfo: { ...deviceInfo, fingerprint: deviceFingerprint, ip: clientIP },
                secureToken,
                isActive: true,
                loginIP: clientIP,
                fromOffice: clientIP === OFFICE_PUBLIC_IP
            };

            sessionsDB.insert(session, (err, newDoc) => {
                if (err) return res.status(500).json({ error: err.message });
                
                logAccessAttempt(employee.id, true, 'Login successful', clientIP, deviceInfo);
                
                res.json({ 
                    success: true, 
                    message: 'تم تسجيل الدخول بنجاح',
                    session: newDoc,
                    employee: { id: employee.id, name: employee.name, empId: employee.empId },
                    secureToken,
                    fromOffice: clientIP === OFFICE_PUBLIC_IP
                });
            });
        });
    });
});

// ✅ تسجيل خروج الموظف
app.post('/api/auth/logout', (req, res) => {
    const { sessionId, empId, secureToken } = req.body;
    if (!sessionId && !empId) return res.status(400).json({ success: false, error: 'مطلوب sessionId أو empId' });

    const query = sessionId ? { sessionId } : { empId, isActive: true };
    
    sessionsDB.findOne(query, (err, session) => {
        if (err || !session) return res.status(404).json({ success: false, error: 'لم يتم العثور على جلسة نشطة' });
        if (secureToken && secureToken !== session.secureToken) return res.status(401).json({ success: false, error: 'توكن غير صالح' });

        const logoutTime = new Date().toISOString();
        const durationHours = (new Date(logoutTime) - new Date(session.loginTime)) / (1000 * 60 * 60);
        
        sessionsDB.update({ _id: session._id }, { $set: { logoutTime, durationHours: parseFloat(durationHours.toFixed(2)), isActive: false } }, {}, (err) => {
            if (err) return res.status(500).json({ error: err.message });

            db_disk.findOne({ type: 'main_db' }, (err, doc) => {
                if (!doc) doc = { employees: [], attendance: {}, payments: {}, type: 'main_db' };
                if (!doc.attendance[session.empId]) doc.attendance[session.empId] = [];
                
                const attendanceRecord = {
                    id: `att_${Date.now()}`,
                    date: new Date(session.loginTime).toISOString().split('T')[0],
                    checkIn: new Date(session.loginTime).toTimeString().substr(0, 5),
                    checkOut: new Date(logoutTime).toTimeString().substr(0, 5),
                    reqHrs: 7,
                    pType: 'normal',
                    deviceInfo: session.deviceInfo,
                    sessionId: session.sessionId,
                    syncStatus: 'synced',
                    fromOffice: session.fromOffice,
                    loginIP: session.loginIP
                };
                
                doc.attendance[session.empId].push(attendanceRecord);
                db_disk.update({ type: 'main_db' }, doc, { upsert: true }, (err) => {
                    if (err) return res.status(500).json({ error: 'فشل حفظ سجل الحضور' });
                    syncLogDB.insert({ type: 'logout', sessionId: session.sessionId, empId: session.empId, timestamp: new Date().toISOString() });
                    res.json({ success: true, message: 'تم تسجيل الخروج', summary: { loginTime: session.loginTime, logoutTime, durationHours: parseFloat(durationHours.toFixed(2)), date: attendanceRecord.date, fromOffice: session.fromOffice } });
                });
            });
        });
    });
});

// ✅ جلب الجلسات النشطة
app.get('/api/auth/sessions', (req, res) => {
    sessionsDB.find({ isActive: true }, (err, docs) => {
        if (err) return res.status(500).json({ error: err.message });
        const sessions = docs.map(s => ({ ...s, currentDurationMinutes: Math.floor((Date.now() - new Date(s.loginTime)) / 60000) }));
        res.json({ success: true, sessions });
    });
});

// ✅ جلب سجل محاولات الدخول (للمشرف)
app.get('/api/auth/access-log', (req, res) => {
    syncLogDB.find({ type: { $in: ['login_success', 'login_blocked'] } })
        .sort({ timestamp: -1 })
        .limit(100)
        .exec((err, docs) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, logs: docs });
        });
});

// ============================================
// 🔄 مسارات المزامنة
// ============================================

app.post('/api/sync/upload', (req, res) => {
    const { deviceInfo, localData } = req.body;
    if (!localData) return res.status(400).json({ success: false, error: 'لا توجد بيانات للمزامنة' });

    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (!doc) doc = { employees: [], attendance: {}, payments: {}, type: 'main_db' };
        
        if (localData.attendance) {
            Object.keys(localData.attendance).forEach(empId => {
                if (!doc.attendance[empId]) doc.attendance[empId] = [];
                localData.attendance[empId].forEach(record => {
                    if (!doc.attendance[empId].find(r => r.id === record.id)) {
                        doc.attendance[empId].push({ ...record, syncStatus: 'synced', syncedAt: new Date().toISOString(), sourceDevice: deviceInfo });
                    }
                });
            });
        }
        if (localData.payments) {
            Object.keys(localData.payments).forEach(empId => {
                if (!doc.payments[empId]) doc.payments[empId] = [];
                localData.payments[empId].forEach(payment => {
                    if (!doc.payments[empId].find(p => p.id === payment.id)) {
                        doc.payments[empId].push({ ...payment, syncStatus: 'synced', syncedAt: new Date().toISOString() });
                    }
                });
            });
        }
        
        db_disk.update({ type: 'main_db' }, doc, { upsert: true }, (err) => {
            if (err) return res.status(500).json({ error: 'فشل المزامنة' });
            syncLogDB.insert({ type: 'sync_upload', deviceInfo, timestamp: new Date().toISOString() });
            res.json({ success: true, message: 'تمت المزامنة', serverTime: new Date().toISOString() });
        });
    });
});

app.get('/api/sync/download', (req, res) => {
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, data: { employees: (doc?.employees || []).map(e => ({ id: e.id, name: e.name, empId: e.empId, department: e.department, allowRemote: e.allowRemote })), lastSync: new Date().toISOString() } });
    });
});

// ============================================
// 📦 المسارات القديمة
// ============================================

app.post('/api/backup', (req, res) => {
    try {
        const { targetPath } = req.body;
        if (!targetPath) return res.status(400).json({ error: 'لم يتم اختيار مسار' });
        fs.copyFileSync(dbPath, targetPath);
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/restore', (req, res) => {
    try {
        const { selectedFilePath } = req.body;
        if (!selectedFilePath) return res.status(400).json({ error: 'لم يتم اختيار ملف' });
        fs.copyFileSync(selectedFilePath, dbPath);
        db_disk.loadDatabase((err) => { if (err) return res.status(500).json({ error: "فشل إعادة التحميل" }); res.json({ success: true }); });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.get('/api/data', (req, res) => {
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).send(err);
        res.json(doc || { employees: [], attendance: {}, payments: {} });
    });
});

app.post('/api/save', (req, res) => {
    const dataToSave = { ...req.body, type: 'main_db' };
    db_disk.update({ type: 'main_db' }, dataToSave, { upsert: true }, (err) => {
        if (err) return res.status(500).json(err);
        res.json({ status: 'success' });
    });
});

// ============================================
// 🚀 تشغيل الخادم
// ============================================

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
    const deviceInfo = getDeviceInfo();
    console.log(`✅ Server running at: http://localhost:${PORT}`);
    console.log(`🌐 Public URL: ${process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`}`);
    console.log(`🔐 Office IP Restriction: ${ENABLE_IP_RESTRICTION ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🏢 Office Public IP: ${OFFICE_PUBLIC_IP}`);
    console.log(`🔐 Fingerprint: ${deviceInfo.fingerprint}`);
});

// ✅ معالجة 404
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found', path: req.path });
});