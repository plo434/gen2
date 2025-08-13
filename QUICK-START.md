# 🚀 Quick Start Guide - Advanced GunDB Messaging Server

## ⚡ البدء السريع في 5 دقائق

### 📋 المتطلبات
- Node.js 16+ 
- npm 8+

### 🚀 الخطوات السريعة

#### 1. تثبيت التبعيات
```bash
npm install
```

#### 2. تشغيل الخادم
```bash
npm start
```

#### 3. فتح المتصفح
```
http://localhost:8080
```

#### 4. اختبار النظام
```bash
node test-client.js
```

---

## 🔧 التكوين السريع

### إنشاء ملف .env
```bash
cp env.example .env
```

### تعديل .env
```bash
# تغيير مفتاح JWT
JWT_SECRET=your-super-secret-key-here

# تغيير المنفذ (اختياري)
PORT=3000
```

---

## 💬 اختبار سريع

### 1. تسجيل مستخدم
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"123456"}'
```

### 2. إرسال رسالة
```bash
curl -X POST http://localhost:8080/api/messages \
  -H "Content-Type: application/json" \
  -d '{"from":"test","to":"user2","content":"مرحبا!","encryptionType":"aes"}'
```

### 3. فحص صحة النظام
```bash
curl http://localhost:8080/api/health
```

---

## 🐳 تشغيل بـ Docker

### تشغيل سريع
```bash
docker-compose up -d
```

### بناء وتشغيل
```bash
docker build -t messaging-server .
docker run -p 8080:8080 messaging-server
```

---

## 📱 النقاط النهائية المتاحة

| النقطة | الطريقة | الوصف |
|--------|----------|-------|
| `/` | GET | واجهة الويب مع التوثيق |
| `/api/health` | GET | فحص صحة النظام |
| `/api/crypto/info` | GET | معلومات التشفير |
| `/api/auth/register` | POST | تسجيل مستخدم جديد |
| `/api/auth/login` | POST | تسجيل الدخول |
| `/api/messages` | POST | إرسال رسالة |
| `/api/messages` | GET | الحصول على الرسائل |
| `/api/users` | GET | قائمة المستخدمين |
| `/api/inbox` | GET | صندوق الوارد |

---

## 🔐 أنواع التشفير

1. **Standard** - بدون تشفير
2. **AES** - تشفير AES-256-CBC
3. **Quantum** - تشفير كمي متقدم (محاكى)

---

## 🚨 استكشاف الأخطاء السريع

### الخادم لا يعمل
```bash
# فحص المنفذ
netstat -an | grep 8080

# فحص Node.js
node --version
```

### خطأ في التبعيات
```bash
# حذف وإعادة تثبيت
rm -rf node_modules package-lock.json
npm install
```

### خطأ في JWT
```bash
# التحقق من .env
cat .env | grep JWT_SECRET
```

---

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

---

## 🎯 الميزات الرئيسية

✅ **JWT Authentication** - مصادقة آمنة  
✅ **Password Hashing** - تشفير كلمات المرور  
✅ **Message Encryption** - تشفير الرسائل  
✅ **Real-time GunDB** - قاعدة بيانات في الوقت الفعلي  
✅ **User Management** - إدارة المستخدمين  
✅ **CORS Enabled** - دعم متعدد المصادر  
✅ **Health Monitoring** - مراقبة صحة النظام  
✅ **Comprehensive Logging** - سجلات شاملة  

---

## 🔗 روابط مفيدة

- **الخادم**: http://localhost:8080
- **صحة النظام**: http://localhost:8080/api/health
- **معلومات التشفير**: http://localhost:8080/api/crypto/info
- **التوثيق الكامل**: README-SIMPLE.md

---

**🎉 مبروك! لديك الآن خادم رسائل متقدم يعمل بكامل طاقته!**
