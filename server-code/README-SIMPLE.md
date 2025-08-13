# 🚀 Advanced GunDB Messaging API Server

## 📋 وصف النظام

خادم رسائل متقدم مبني على **GunDB** مع ميزات أمان متطورة:
- **JWT Authentication** - مصادقة آمنة
- **Password Hashing** - تشفير كلمات المرور
- **Message Encryption** - تشفير الرسائل
- **Real-time Messaging** - رسائل في الوقت الفعلي
- **User Management** - إدارة المستخدمين

## 🔐 الميزات الأمنية

### أنواع التشفير:
1. **Standard** - بدون تشفير (نص عادي)
2. **AES** - تشفير AES-256-CBC
3. **Quantum** - تشفير كمي متقدم (محاكى)

### الأمان:
- JWT tokens مع انتهاء صلاحية 24 ساعة
- تشفير كلمات المرور باستخدام bcrypt
- تخزين آمن للبيانات
- CORS enabled

## 🚀 التثبيت والتشغيل

### 1. تثبيت التبعيات
```bash
npm install
```

### 2. تشغيل الخادم
```bash
# التشغيل العادي
npm start

# وضع التطوير (مع إعادة التشغيل التلقائي)
npm run dev
```

### 3. الوصول للخادم
```
http://localhost:8080
```

## 📡 نقاط النهاية (API Endpoints)

### المصادقة (Authentication)
- `POST /api/auth/register` - تسجيل مستخدم جديد
- `POST /api/auth/login` - تسجيل الدخول

### الرسائل (Messages)
- `POST /api/messages` - إرسال رسالة مشفرة
- `GET /api/messages` - الحصول على الرسائل
- `DELETE /api/messages` - حذف رسالة

### المستخدمين (Users)
- `POST /api/users` - إنشاء مستخدم (توافق مع الإصدار السابق)
- `GET /api/users` - الحصول على قائمة المستخدمين

### صندوق الوارد (Inbox)
- `GET /api/inbox` - الحصول على صندوق الوارد
- `DELETE /api/inbox` - مسح صندوق الوارد

### النظام (System)
- `GET /` - واجهة الويب مع التوثيق
- `GET /api/health` - فحص صحة النظام
- `GET /api/crypto/info` - معلومات نظام التشفير

## 💬 استخدام النظام

### 1. تسجيل مستخدم جديد
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "email": "user1@example.com",
    "password": "password123"
  }'
```

### 2. تسجيل الدخول
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "password": "password123"
  }'
```

### 3. إرسال رسالة مشفرة
```bash
curl -X POST http://localhost:8080/api/messages \
  -H "Content-Type: application/json" \
  -d '{
    "from": "user1",
    "to": "user2",
    "content": "مرحبا! هذه رسالة مشفرة",
    "encryptionType": "aes"
  }'
```

### 4. الحصول على صندوق الوارد
```bash
curl "http://localhost:8080/api/inbox?userId=user2"
```

## 🔧 التكوين

### متغيرات البيئة (Environment Variables)
```bash
# نسخ ملف البيئة
cp env.example .env

# تعديل الملف
PORT=8080                    # منفذ الخادم (افتراضي: 8080)
JWT_SECRET=your-secret-key  # مفتاح JWT السري
```

### تغيير المنفذ
```bash
# في Linux/Mac
export PORT=3000
npm start

# في Windows
set PORT=3000
npm start
```

## 📊 بنية البيانات

### رسالة (Message)
```json
{
  "id": "message_id",
  "from": "sender_username",
  "to": "recipient_username",
  "content": "encrypted_content",
  "originalContent": "original_text",
  "timestamp": 1234567890,
  "encrypted": true,
  "encryption": {
    "type": "aes",
    "algorithm": "AES-256-CBC",
    "key": "base64_key",
    "iv": "base64_iv"
  }
}
```

### مستخدم (User)
```json
{
  "username": "username",
  "email": "email@example.com",
  "passwordHash": "hashed_password",
  "createdAt": 1234567890,
  "status": "active"
}
```

## 🔒 الأمان

### JWT Token
- انتهاء صلاحية: 24 ساعة
- يحتوي على: username, email, iat, exp
- توقيع باستخدام: JWT_SECRET

### تشفير كلمات المرور
- خوارزمية: bcrypt
- salt rounds: 12
- آمن ضد: rainbow tables, brute force

### تشفير الرسائل
- **Standard**: بدون تشفير
- **AES**: AES-256-CBC مع IV عشوائي
- **Quantum**: AES-256-GCM مع auth tag

## 🚀 النشر على السيرفر

### 1. رفع الملفات
```bash
# رفع الملفات إلى السيرفر
scp advanced-simple-server.js user@server:/path/to/app/
scp package.json user@server:/path/to/app/
```

### 2. تثبيت وتشغيل
```bash
cd /path/to/app
npm install --production
npm start
```

### 3. استخدام PM2 (مستحسن)
```bash
npm install -g pm2
pm2 start advanced-simple-server.js --name "messaging-server"
pm2 startup
pm2 save
```

## 🧪 اختبار النظام

### تشغيل جميع الاختبارات
```bash
node test-client.js
```

### اختبارات فردية
```bash
# فحص صحة النظام
curl http://localhost:8080/api/health

# معلومات التشفير
curl http://localhost:8080/api/crypto/info

# قائمة المستخدمين
curl http://localhost:8080/api/users
```

## 📝 السجلات

### سجلات الطلبات
```
[2024-01-01T12:00:00.000Z] POST /api/auth/register
[2024-01-01T12:00:01.000Z] POST /api/auth/login
[2024-01-01T12:00:02.000Z] POST /api/messages
```

### سجلات النظام
```
🚀 [Advanced Messaging Server] API server running at http://localhost:8080
🔐 [Advanced Messaging Server] Features: JWT Auth, Password Hashing, Message Encryption
📦 [Advanced Messaging Server] GunDB relay initialized and ready
🔒 [Advanced Messaging Server] Encryption types: Standard, AES, Quantum
```

## 🔧 استكشاف الأخطاء

### مشاكل شائعة:

1. **Port already in use**
   ```bash
   # تغيير المنفذ
   export PORT=3000
   npm start
   ```

2. **JWT verification failed**
   ```bash
   # التحقق من JWT_SECRET
   echo $JWT_SECRET
   ```

3. **GunDB connection issues**
   ```bash
   # إعادة تشغيل الخادم
   npm restart
   ```

## 📚 الملفات المهمة

- `advanced-simple-server.js` - الخادم الرئيسي
- `package.json` - التبعيات
- `test-client.js` - عميل الاختبار
- `start.sh` - سكريبت التشغيل
- `start.bat` - سكريبت التشغيل (Windows)
- `deploy.sh` - سكريبت النشر
- `Dockerfile` - ملف Docker
- `docker-compose.yml` - تكوين Docker
- `env.example` - مثال متغيرات البيئة

## 🎯 الميزات الرئيسية

✅ **JWT Authentication** - مصادقة آمنة  
✅ **Password Hashing** - تشفير كلمات المرور  
✅ **Message Encryption** - تشفير الرسائل  
✅ **Real-time GunDB** - قاعدة بيانات في الوقت الفعلي  
✅ **User Management** - إدارة المستخدمين  
✅ **CORS Enabled** - دعم متعدد المصادر  
✅ **Health Monitoring** - مراقبة صحة النظام  
✅ **Comprehensive Logging** - سجلات شاملة  

## 🔗 روابط مفيدة

- **الخادم**: http://localhost:8080
- **صحة النظام**: http://localhost:8080/api/health
- **معلومات التشفير**: http://localhost:8080/api/crypto/info

## 📄 الترخيص

MIT License - انظر ملف LICENSE للتفاصيل

---

**تم إنشاء هذا النظام بواسطة فريق التطوير المتقدم** 🚀
