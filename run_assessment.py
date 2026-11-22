"""Run one complete AI Security Agent assessment without Swagger/API calls."""

import sys
import time
import traceback
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))


def print_stage(message):
    print("\n" + "=" * 72)
    print(message)
    print("=" * 72, flush=True)


def main():
    application_ids = ["sakha_register"]

    print_stage("مرحله ۱ از ۶: بارگذاری سرویس‌ها و بررسی تنظیمات")
    from app.services.zap_service import zap_service
    from app.services.security_assessment_orchestrator import (
        security_assessment_orchestrator as orchestrator
    )
    from app.main import analyze_assessment, generate_assessment_report

    import browser_auth
    import json
    from datetime import datetime, timezone

    print("پروژه:", PROJECT_DIR)
    print("اپلیکیشن‌ها:", ", ".join(application_ids))

    try:
        zap_status = zap_service.is_connected()
        print("وضعیت اتصال ZAP:", zap_status)
    except Exception as exc:
        raise RuntimeError(
            "ارتباط با OWASP ZAP برقرار نشد. ابتدا ZAP را اجرا و تنظیمات .env را بررسی کنید."
        ) from exc

    print_stage("مرحله ۲ از ۶: ایجاد ارزیابی جدید")
    assessment = orchestrator.create_assessment(application_ids)
    assessment_id = assessment["assessment_id"]
    print("شناسه ارزیابی:", assessment_id)

    print_stage("مرحله ۳ از ۶: اجرای مرورگر و پیمایش صفحات با Playwright")
    assessment = orchestrator.get_assessment(assessment_id)
    assessment["status"] = "crawl_running"
    assessment["updated_at"] = datetime.now(timezone.utc).isoformat()
    orchestrator.save_assessment(assessment)

    # Runs in the foreground. CAPTCHA/OTP are the only expected manual actions;
    # the browser closes automatically when the configured crawl is finished.
    summary = browser_auth.main(
        application_ids=application_ids,
        wait_for_exit=False
    )

    crawl_directory = PROJECT_DIR / "data" / "crawl_results"
    crawl_results = {}
    crawl_errors = []

    for application in application_ids:
        result_file = crawl_directory / f"{application}_crawl.json"
        if not result_file.is_file():
            crawl_errors.append({
                "application": application,
                "error": "Playwright crawl result file was not created"
            })
            continue

        with result_file.open("r", encoding="utf-8") as file:
            result = json.load(file)

        if not isinstance(result, dict) or result.get("application") != application:
            crawl_errors.append({
                "application": application,
                "error": "Invalid Playwright crawl result"
            })
            continue

        crawl_results[application] = result
        if result.get("termination_reason") == "application_failed":
            crawl_errors.append({
                "application": application,
                "error": "Playwright could not complete this application's crawl"
            })

    assessment["crawl_results"] = crawl_results
    assessment["crawl_summary"] = summary if isinstance(summary, dict) else {}
    assessment["crawl_errors"] = crawl_errors
    assessment["status"] = (
        "crawl_completed"
        if len(crawl_results) == len(application_ids) and not crawl_errors
        else "crawl_completed_with_errors"
    )
    assessment["updated_at"] = datetime.now(timezone.utc).isoformat()
    orchestrator.save_assessment(assessment)

    crawl_status = assessment["status"]
    print("وضعیت پیمایش:", crawl_status)
    print("خلاصه پیمایش:", assessment.get("crawl_summary", {}))

    if not crawl_results:
        raise RuntimeError(
            "هیچ نتیجه معتبری از پیمایش دریافت نشد. جزئیات در data/assessments.json ثبت شده است."
        )

    print_stage("مرحله ۴ از ۶: انتظار برای تکمیل ZAP Passive Scan")
    passive_result = orchestrator.wait_for_passive_scan(
        assessment_id,
        timeout=1800,
        poll_interval=5
    )
    print(passive_result)

    print_stage("مرحله ۵ از ۶: جمع‌آوری هشدارها و تحلیل امنیتی")
    collection_result = orchestrator.collect_zap_findings(assessment_id)
    print("تعداد هشدارهای جمع‌آوری‌شده:", collection_result.get("total_findings"))
    print("وضعیت جمع‌آوری:", collection_result.get("status"))

    analysis_result = analyze_assessment(
        assessment_id=assessment_id,
        request=None
    )
    print("وضعیت تحلیل:", analysis_result.get("status"))
    print("تعداد یافته‌ها:", analysis_result.get("total_findings"))

    print_stage("مرحله ۶ از ۶: تولید گزارش فارسی")
    report_result = generate_assessment_report(assessment_id)
    print(report_result)

    report_id = report_result.get("report_id")
    report_dir = PROJECT_DIR / "app" / "reports"
    if not report_dir.exists():
        # Report service may use a project-level reports directory.
        from app.services.security_report_service import security_report_service
        report_dir = Path(security_report_service.report_directory)

    print_stage("ارزیابی با موفقیت به پایان رسید")
    print("شناسه ارزیابی:", assessment_id)
    print("شناسه گزارش:", report_id)
    print("پوشه گزارش‌ها:", report_dir)
    print("فایل HTML:", report_dir / f"{report_id}.html")
    print("فایل JSON:", report_dir / f"{report_id}.json")
    print("اطلاعات کامل ارزیابی: data/assessments.json")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nاجرای ارزیابی توسط کاربر متوقف شد.")
        raise SystemExit(130)
    except Exception as exc:
        print("\nخطا در اجرای ارزیابی:", str(exc))
        traceback.print_exc()
        print("\nشناسه/وضعیت ارزیابی در صورت ایجاد، در data/assessments.json باقی می‌ماند.")
        input("برای بستن پنجره Enter بزنید...")
        raise SystemExit(1)
