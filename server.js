const express = require('express');
const Datastore = require('@seald-io/nedb'); 
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto'); // للتشفير

const app = express();

// --- 1. إعداد المسارات ---
// في بداية server.js - استبدل جزء إعداد المسارات بهذا:

const appDataPath = process.env.RENDER ? '/data' : path.join(process.env.APPDATA || './', 'SalaryApp');
const dbPath = path.join(appDataPath, 'salary_data.db');
const syncLogPath = path.join(appDataPath, 'sync_log.db');
const uploadsPath = path.join(appDataPath, 'uploads');

// إنشاء المجلدات إذا لم تكن موجودة
[appDataPath, uploadsPath].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// --- 2. تهيئة قواعد البيانات ---
const db_disk = new Datastore({ filename: dbPath, autoload: true });
const syncLogDB = new Datastore({ filename: syncLogPath, autoload: true }); // لتتبع المزامنة
const sessionsDB = new Datastore({ filename: path.join(appDataPath, 'sessions.db'), autoload: true });

// إعدادات Express
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// --- 3. دوال مساعدة للأمان ---
function generateDeviceFingerprint() {
    // بصمة فريدة للجهاز تمنع التلاعب
    const info = [
        os.hostname(),
        os.userInfo().username,
        os.platform(),
        os.totalmem(),
        os.cpus()[0]?.model
    ].join('|');
    return crypto.createHash('sha256').update(info).digest('hex').substr(0, 16);
}

function getDeviceInfo() {
    return {
        hostname: os.hostname(),
        username: os.userInfo().username,
        platform: os.platform(),
        fingerprint: generateDeviceFingerprint(),
        ip: Object.values(os.networkInterfaces())
            .flat()
            .find(i => i?.family === 'IPv4' && !i.internal)?.address || 'unknown',
        timestamp: new Date().toISOString()
    };
}

function generateSessionId() {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateSecureToken(empId, deviceFingerprint) {
    // توكن مشفر يربط الموظف بالجهاز
    return crypto.createHash('sha256')
        .update(`${empId}|${deviceFingerprint}|${process.env.SECRET_KEY || 'default_secret'}`)
        .digest('hex');
}

// --- 4. API: تسجيل دخول الموظف (محمي) ---
app.post('/api/auth/login', (req, res) => {
    const { empId, pin, deviceInfo } = req.body;
    
    if (!empId || !pin) {
        return res.status(400).json({ success: false, error: 'يرجى إدخال الرقم الوظيفي ورمز الدخول' });
    }

    // التحقق من بصمة الجهاز
    const deviceFingerprint = deviceInfo?.fingerprint || generateDeviceFingerprint();
    
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const employee = (doc?.employees || []).find(e => e.empId === empId && e.pin === pin);
        
        if (!employee) {
            // تسجيل محاولة دخول فاشلة للأمان
            syncLogDB.insert({
                type: 'failed_login',
                empId,
                deviceInfo,
                timestamp: new Date().toISOString()
            });
            return res.status(401).json({ success: false, error: 'الرقم الوظيفي أو رمز الدخول غير صحيح' });
        }

        // التحقق من عدم وجود جلسة نشطة لنفس الموظف
        sessionsDB.findOne({ empId: employee.id, isActive: true }, (err, activeSession) => {
            if (activeSession) {
                // منع تسجيل الدخول من جهازين في نفس الوقت
                return res.status(400).json({ 
                    success: false, 
                    error: 'هذا الموظف مسجل دخول بالفعل على جهاز آخر',
                    device: activeSession.deviceInfo?.hostname
                });
            }

            // إنشاء توكن آمن للموظف
            const secureToken = generateSecureToken(employee.id, deviceFingerprint);

            // إنشاء جلسة جديدة
            const session = {
                sessionId: generateSessionId(),
                empId: employee.id,
                empName: employee.name,
                empCode: employee.empId,
                loginTime: new Date().toISOString(),
                deviceInfo: { ...deviceInfo, fingerprint: deviceFingerprint },
                secureToken,
                isActive: true
            };

            sessionsDB.insert(session, (err, newDoc) => {
                if (err) return res.status(500).json({ error: err.message });
                
                // تسجيل في سجل المزامنة
                syncLogDB.insert({
                    type: 'login',
                    sessionId: newDoc.sessionId,
                    empId: employee.id,
                    deviceInfo,
                    timestamp: new Date().toISOString()
                });
                
                res.json({ 
                    success: true, 
                    message: 'تم تسجيل الدخول بنجاح',
                    session: newDoc,
                    employee: { id: employee.id, name: employee.name, empId: employee.empId },
                    secureToken
                });
            });
        });
    });
});

// --- 5. API: تسجيل الخروج (محمي) ---
app.post('/api/auth/logout', (req, res) => {
    const { sessionId, empId, secureToken } = req.body;
    
    if (!sessionId && !empId) {
        return res.status(400).json({ success: false, error: 'مطلوب sessionId أو empId' });
    }

    const query = sessionId ? { sessionId } : { empId, isActive: true };
    
    sessionsDB.findOne(query, (err, session) => {
        if (err || !session) {
            return res.status(404).json({ success: false, error: 'لم يتم العثور على جلسة نشطة' });
        }

        // التحقق من التوكن الأمني (لمنع التلاعب)
        if (secureToken && secureToken !== session.secureToken) {
            return res.status(401).json({ success: false, error: 'توكن غير صالح - محاولة تلاعب محتملة' });
        }

        const logoutTime = new Date().toISOString();
        const loginDate = new Date(session.loginTime);
        const logoutDate = new Date(logoutTime);
        const durationHours = (logoutDate - loginDate) / (1000 * 60 * 60);
        
        // تحديث الجلسة
        sessionsDB.update({ _id: session._id }, { 
            $set: { 
                logoutTime, 
                durationHours: parseFloat(durationHours.toFixed(2)),
                isActive: false 
            } 
        }, {}, (err) => {
            if (err) return res.status(500).json({ error: err.message });

            // إضافة سجل الحضور تلقائياً
            db_disk.findOne({ type: 'main_db' }, (err, doc) => {
                if (!doc) doc = { employees: [], attendance: {}, payments: {}, type: 'main_db' };
                
                if (!doc.attendance[session.empId]) doc.attendance[session.empId] = [];
                
                const attendanceRecord = {
                    id: `att_${Date.now()}`,
                    date: loginDate.toISOString().split('T')[0],
                    checkIn: loginDate.toTimeString().substr(0, 5),
                    checkOut: logoutDate.toTimeString().substr(0, 5),
                    reqHrs: session.employeeDailyHours || 7,
                    pType: 'normal',
                    deviceInfo: session.deviceInfo,
                    sessionId: session.sessionId,
                    syncStatus: 'synced' // حالة المزامنة
                };
                
                doc.attendance[session.empId].push(attendanceRecord);
                
                db_disk.update({ type: 'main_db' }, doc, { upsert: true }, (err) => {
                    if (err) return res.status(500).json({ error: 'فشل حفظ سجل الحضور: ' + err.message });
                    
                    // تسجيل المزامنة
                    syncLogDB.insert({
                        type: 'logout',
                        sessionId: session.sessionId,
                        empId: session.empId,
                        attendanceId: attendanceRecord.id,
                        timestamp: new Date().toISOString()
                    });
                    
                    res.json({ 
                        success: true, 
                        message: 'تم تسجيل الخروج وحفظ الدوام',
                        summary: {
                            loginTime: session.loginTime,
                            logoutTime,
                            durationHours: parseFloat(durationHours.toFixed(2)),
                            date: attendanceRecord.date
                        }
                    });
                });
            });
        });
    });
});

// --- 6. API: مزامنة البيانات من الأجهزة المحلية ---
app.post('/api/sync/upload', (req, res) => {
    const { deviceInfo, localData, syncToken } = req.body;
    
    if (!localData) {
        return res.status(400).json({ success: false, error: 'لا توجد بيانات للمزامنة' });
    }

    // التحقق من التوكن (يمكن تطويره ليكون أكثر أماناً)
    // هنا نقبل المزامنة من أي جهاز مصرح له
    
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (!doc) doc = { employees: [], attendance: {}, payments: {}, type: 'main_db' };
        
        // دمج سجلات الحضور
        if (localData.attendance) {
            Object.keys(localData.attendance).forEach(empId => {
                if (!doc.attendance[empId]) doc.attendance[empId] = [];
                
                localData.attendance[empId].forEach(record => {
                    // تجنب التكرار
                    const exists = doc.attendance[empId].find(r => r.id === record.id);
                    if (!exists) {
                        record.syncStatus = 'synced';
                        record.syncedAt = new Date().toISOString();
                        record.sourceDevice = deviceInfo;
                        doc.attendance[empId].push(record);
                    }
                });
            });
        }
        
        // دمج الدفعات
        if (localData.payments) {
            Object.keys(localData.payments).forEach(empId => {
                if (!doc.payments[empId]) doc.payments[empId] = [];
                
                localData.payments[empId].forEach(payment => {
                    const exists = doc.payments[empId].find(p => p.id === payment.id);
                    if (!exists) {
                        payment.syncStatus = 'synced';
                        payment.syncedAt = new Date().toISOString();
                        doc.payments[empId].push(payment);
                    }
                });
            });
        }
        
        db_disk.update({ type: 'main_db' }, doc, { upsert: true }, (err) => {
            if (err) return res.status(500).json({ error: 'فشل المزامنة: ' + err.message });
            
            syncLogDB.insert({
                type: 'sync_upload',
                deviceInfo,
                recordsCount: Object.keys(localData.attendance || {}).length,
                timestamp: new Date().toISOString()
            });
            
            res.json({ 
                success: true, 
                message: 'تمت المزامنة بنجاح',
                serverTime: new Date().toISOString()
            });
        });
    });
});

// --- 7. API: جلب البيانات للمزامنة ---
app.get('/api/sync/download', (req, res) => {
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // نرسل فقط البيانات الضرورية للموظف (ليس كل شيء)
        const safeData = {
            employees: (doc?.employees || []).map(e => ({
                id: e.id,
                name: e.name,
                empId: e.empId,
                department: e.department
            })),
            lastSync: new Date().toISOString()
        };
        
        res.json({ success: true, data: safeData });
    });
});

// --- 8. API: جلب الجلسات النشطة (للمشرف) ---
app.get('/api/auth/sessions', (req, res) => {
    sessionsDB.find({ isActive: true }, (err, docs) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const sessions = docs.map(s => {
            const start = new Date(s.loginTime);
            const now = new Date();
            const currentDuration = (now - start) / (1000 * 60);
            return { ...s, currentDurationMinutes: Math.floor(currentDuration) };
        });
        
        res.json({ success: true, sessions });
    });
});

// --- 9. API: سجل المزامنة (للمشرف) ---
app.get('/api/sync/log', (req, res) => {
    syncLogDB.find({}).sort({ timestamp: -1 }).limit(100, (err, docs) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, logs: docs });
    });
});

// --- 10. المسارات القديمة ---
app.post('/api/backup', (req, res) => {
    try {
        const { targetPath } = req.body; 
        if (!targetPath) return res.status(400).json({ error: 'لم يتم اختيار مسار' });
        fs.copyFileSync(dbPath, targetPath);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/restore', (req, res) => {
    try {
        const { selectedFilePath } = req.body;
        if (!selectedFilePath) return res.status(400).json({ error: 'لم يتم اختيار ملف' });
        fs.copyFileSync(selectedFilePath, dbPath);
        db_disk.loadDatabase((err) => {
            if (err) return res.status(500).json({ error: "فشل إعادة تحميل البيانات" });
            res.json({ success: true });
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/data', (req, res) => {
    db_disk.findOne({ type: 'main_db' }, (err, doc) => {
        if (err) return res.status(500).send(err);
        res.json(doc || { employees: [], attendance: {}, payments: {} });
    });
});

app.post('/api/save', (req, res) => {
    const dataToSave = req.body;
    dataToSave.type = 'main_db';
    db_disk.update({ type: 'main_db' }, dataToSave, { upsert: true }, (err) => {
        if (err) return res.status(500).json(err);
        res.json({ status: 'success' });
    });
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.RENDER ? '0.0.0.0' : '0.0.0.0';

app.listen(PORT, HOST, () => {
    const deviceInfo = getDeviceInfo();
    console.log(`✅ Server running at: http://localhost:${PORT}`);
    console.log(`🌐 Public URL: ${process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`}`);
    console.log(`🔐 Device Fingerprint: ${deviceInfo.fingerprint}`);
});
