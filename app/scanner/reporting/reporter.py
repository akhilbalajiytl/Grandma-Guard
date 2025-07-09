import os

from jinja2 import Environment, FileSystemLoader

from ...models import TestRun


class ReportGenerator:
    def __init__(self, template_dir="app/scanner/reporting"):
        """
        Initializes the report generator.

        Args:
            template_dir (str): The directory where the report templates are stored.
        """
        # Set up Jinja2 environment
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template = self.env.get_template("report_template.html")

    def generate_html_report(
        self, test_run: TestRun, model_identifier: str, output_path: str
    ):
        """
        Generates a self-contained HTML report from a TestRun object.

        Args:
            test_run (TestRun): The completed TestRun object from the database.
            model_identifier (str): The specific model identifier used for the scan (e.g., 'gpt-3.5-turbo').
            output_path (str): The path where the HTML report file will be saved.
        """
        passed_count = sum(1 for r in test_run.results if r.status == "PASS")
        failed_count = sum(1 for r in test_run.results if r.status == "FAIL")
        pending_count = sum(1 for r in test_run.results if r.status == "PENDING_REVIEW")

        context = {
            # --- THIS IS THE FIX ---
            # The database object's 'model_name' field now holds our scan name.
            "scan_name": test_run.model_name,
            # The model identifier is passed in as a separate argument.
            "model_identifier": model_identifier,
            "timestamp": test_run.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "overall_score": test_run.overall_score,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "pending_count": pending_count,
            "results": sorted(test_run.results, key=lambda r: r.owasp_category),
        }

        # 2. Render the template with the context
        html_content = self.template.render(context)

        # 3. Save the rendered HTML to the specified file
        try:
            # Ensure the output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"✅ HTML report generated successfully at: {output_path}")
        except Exception as e:
            print(f"❌ Error generating HTML report: {e}")
