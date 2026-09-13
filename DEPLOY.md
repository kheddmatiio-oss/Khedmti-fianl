# Khedmti — نشر المشروع من الصفر

## 1. Supabase

1. [supabase.com/dashboard](https://supabase.com/dashboard) → **New project**
   - الاسم: `khedmti`
   - Region: **West EU (Ireland)** (الأقرب للجزائر)
   - احفظ Database Password
2. استنى حتى يخلص التجهيز (~دقيقتين). إذا الدومين ما يجاوبش فوراً، هذا عادي.
3. **SQL Editor** → الصق `supabase/00_setup.sql` كامل → **Run**
4. **Project Settings → API** → انسخ:
   - `Project URL`
   - `publishable key` (ماشي `secret`)

## 2. اربط الكود

في `index.html` بدّل السطرين:

```js
const SUPABASE_URL='https://<ref>.supabase.co';
const SUPABASE_KEY='sb_publishable_...';
```

ثم `cp index.html v2.html` باش يبقاو متطابقين.

## 3. حسابك

1. حل المنصة → **سجل وكالتك مجاناً** → دخل بياناتك
2. رجع لـ SQL Editor:

```sql
update agencies set is_super = true where email = 'انت@الايميل.com';
```

3. اخرج وعاود ادخل → تدخل على لوحة المدير العام.

## 4. Netlify

مربوط بـ GitHub (`khilonahilo01-cpu/platformedit`)، ينشر تلقائياً من `main`.

- Publish directory: `.`
- `netlify.toml` يوجّه كلشي على `index.html`

```bash
git add -A && git commit -m "..." && git push
```

---

## ⚠️ توقّف المشروع المجاني

مشاريع Supabase المجانية **تتوقف بعد ~7 أيام بلا استعمال**، ووقتها الدومين
يرجع `NXDOMAIN` — يبان وكأنه عطل شبكة، بصح `supabase.com` يبقى يجاوب.

**التشخيص قبل ما تبدّل أي كود:**

```bash
nslookup <ref>.supabase.co 8.8.8.8
```

- `NXDOMAIN` → المشروع موقوف. Dashboard → **Restore**. البيانات ما تروحش.
- يجاوب بعنوان → المشكلة في حاجة أخرى.

صار 3 مرات. كي تحل للزباين، **الترقية لـ Pro هي الحل الوحيد المعقول** —
ولا حط cron يزور المنصة كل يومين.

## وضع تجريبي محلي

إذا Supabase مقفول وتحتاج تجرّب ولا توري المنصة: في شاشة الخطأ اضغط
**🧪 وضع تجريبي محلي**. المنصة تخدم كاملة، البيانات في المتصفح وحدو،
وشارة ثابتة تبيّن بلي راك في الوضع التجريبي.

## الملفات

| | |
|---|---|
| `index.html` | التطبيق كامل (ملف واحد، بلا build) |
| `v2.html` | نسخة مطابقة |
| `supabase/00_setup.sql` | **تنصيب من الصفر** — هذا اللي تستعملو |
| `supabase/01_secure_auth.sql` | ترقية قاعدة قديمة فقط |
| `brand/` | الشعارات + قواعد الهوية |
