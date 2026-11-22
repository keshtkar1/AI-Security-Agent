# AI Security Agent - Playwright Integration Patch

این بسته فقط سه فایل را تغییر می‌دهد:

1. `browser_auth.py` در ریشه پروژه
2. `app/services/security_assessment_orchestrator.py`
3. `app/main.py`

## نصب
از پروژه فعلی یک کپی پشتیبان بگیرید، سپس فایل‌های داخل ZIP را دقیقاً در مسیرهای بالا جایگزین کنید.

## اجرای جریان جدید
1. FastAPI را اجرا کنید: `py -m app.main`
2. در Swagger یک Assessment بسازید: `POST /assessments` با `{"applications":["sakha_register"]}`
3. برای شناسه ایجادشده، `POST /assessments/{assessment_id}/crawl` را اجرا کنید.
4. مرورگر باز می‌شود. نام کاربری، رمز، CAPTCHA و OTP را طبق پیام‌های ترمینال وارد کنید.
5. پس از ورود، در مرورگر به سامانه ثبت ساکنان بروید؛ سپس در ترمینال Enter بزنید تا crawler تب/صفحه را تشخیص دهد.
6. صفحات فقط از `applications.json` و به ترتیب تعریف‌شده پیمایش می‌شوند. پس از پایان crawl، در ترمینال Enter بزنید تا مرورگر بسته شود.
7. وضعیت را با `GET /assessments/{assessment_id}` بررسی کنید. باید `crawl_completed` یا `crawl_completed_with_errors` باشد.
8. سپس `POST /assessments/{assessment_id}/passive-scan`، بعد `/collect`، `/analyze` و `/report` را اجرا کنید.

`/spider` عمداً با HTTP 410 غیرفعال شده است. `/run` اکنون فقط crawl را شروع می‌کند، چون CAPTCHA/OTP نیازمند تعامل دستی است و مراحل بعدی باید پس از اتمام crawl انجام شوند.

نتایج جزئی هر برنامه از `data/crawl_results/{application}_crawl.json` خوانده و داخل همان Assessment در `crawl_results` ذخیره می‌شوند. خطای crawl به‌عنوان صفر یافته ثبت نمی‌شود.
