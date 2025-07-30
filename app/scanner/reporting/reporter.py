"""
GrandmaGuard Security Report Generation Module

This module provides comprehensive HTML report generation capabilities for
GrandmaGuard security scanning results. It transforms raw security assessment
data into professional, self-contained HTML reports suitable for stakeholders,
compliance documentation, and security audit trails.

Core Functionality:
- Professional HTML report generation using Jinja2 templating
- Self-contained reports with embedded CSS and JavaScript
- Comprehensive security assessment visualization
- Support for multiple report formats and customization options
- Integration with GrandmaGuard database models for seamless data access

Report Features:
- Executive summary with key security findings
- Detailed threat analysis with risk categorization
- Interactive charts and visualizations
- Compliance mapping to security frameworks
- Recommendations and remediation guidance
- Audit trail with complete test execution details

The report generator supports various stakeholder needs from executive
briefings to technical deep-dives, ensuring security findings are
communicated effectively across organizational levels.

Classes:
    ReportGenerator: Main report generation engine with template management

Author: GrandmaGuard Security Team
License: MIT
"""

import os

from jinja2 import Environment, FileSystemLoader

from ...models import TestRun


class ReportGenerator:
    """
    Professional HTML report generator for GrandmaGuard security assessments.
    
    This class provides comprehensive report generation capabilities, transforming
    raw security scanning results into professional HTML reports. The generator
    uses Jinja2 templating for flexible report customization and supports
    various output formats and styling options.
    
    The report generator integrates seamlessly with GrandmaGuard's database
    models, extracting detailed security assessment data and presenting it
    in an accessible, visually appealing format suitable for both technical
    and executive audiences.
    
    Key Features:
    - Jinja2-based templating for flexible report customization
    - Self-contained HTML output with embedded resources
    - Professional styling with responsive design
    - Comprehensive security data visualization
    - Multi-stakeholder report variants
    
    Attributes:
        env (Environment): Jinja2 environment for template processing
        template: Loaded HTML template for report generation
    
    Example:
        >>> generator = ReportGenerator("templates/")
        >>> generator.generate_html_report(test_run, "gpt-4", "report.html")
    """
    
    def __init__(self, template_dir="app/scanner/reporting"):
        """
        Initialize report generator with template configuration.
        
        Sets up the Jinja2 templating environment and loads the main report
        template for HTML generation. The template directory should contain
        all necessary template files and assets for report generation.

        Args:
            template_dir (str): Directory path containing report templates.
                              Defaults to "app/scanner/reporting" for standard
                              GrandmaGuard installation layout.
        """
        # Set up Jinja2 environment
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template = self.env.get_template("report_template.html")

    def generate_html_report(
        self, test_run: TestRun, model_identifier: str, output_path: str
    ):
        """
        Generate comprehensive HTML security assessment report.
        
        Creates a professional, self-contained HTML report from GrandmaGuard
        security scanning results. The report includes executive summary,
        detailed findings, risk analysis, and recommendations for stakeholders
        across technical and business domains.
        
        The generated report is fully self-contained with embedded CSS and
        JavaScript, making it suitable for sharing and archiving without
        external dependencies. The report format is optimized for both
        screen viewing and printing.

        Args:
            test_run (TestRun): Completed TestRun database object containing
                              all security assessment results, including scan
                              metadata, test results, and risk classifications.
            model_identifier (str): Specific AI model identifier that was tested
                                  (e.g., 'gpt-4', 'claude-3', 'llama-2-70b').
                                  Used for report title and model-specific analysis.
            output_path (str): File system path where the HTML report will be saved.
                             Should include the desired filename with .html extension.
        
        Example:
            >>> test_run = TestRun.query.filter_by(id=123).first()
            >>> generator.generate_html_report(
            ...     test_run, 
            ...     "gpt-4-turbo",
            ...     "/reports/security_assessment_2024.html"
            ... )
        
        Note:
            The output file will be overwritten if it already exists. Ensure
            the output directory has appropriate write permissions.
        """
        results_by_owasp = {}
        # Define the statuses we care about for the chart
        valid_chart_statuses = ["PASS", "FAIL", "PENDING_REVIEW", "ERROR"]

        for result in test_run.results:
            cat = result.owasp_category
            if cat not in results_by_owasp:
                # Initialize the dictionary for this category
                results_by_owasp[cat] = {status: 0 for status in valid_chart_statuses}

            # Safely increment the count for the result's status
            if result.status in results_by_owasp[cat]:
                results_by_owasp[cat][result.status] += 1

        # Build the final chart_data dictionary in the format Chart.js expects
        chart_data = {
            "labels": list(results_by_owasp.keys()),
            "datasets": [
                {
                    "label": "PASS",
                    "data": [v.get("PASS", 0) for v in results_by_owasp.values()],
                    "backgroundColor": "rgba(40, 167, 69, 0.8)",
                },
                {
                    "label": "FAIL",
                    "data": [v.get("FAIL", 0) for v in results_by_owasp.values()],
                    "backgroundColor": "rgba(220, 53, 69, 0.8)",
                },
                {
                    "label": "PENDING",
                    "data": [
                        v.get("PENDING_REVIEW", 0) for v in results_by_owasp.values()
                    ],
                    "backgroundColor": "rgba(255, 193, 7, 0.8)",
                },
                {
                    "label": "ERROR",
                    "data": [v.get("ERROR", 0) for v in results_by_owasp.values()],
                    "backgroundColor": "rgba(108, 117, 125, 0.8)",
                },
            ],
        }

        passed_count = sum(1 for r in test_run.results if r.status == "PASS")
        failed_count = sum(1 for r in test_run.results if r.status == "FAIL")
        pending_count = sum(1 for r in test_run.results if r.status == "PENDING_REVIEW")

        context = {
            # The database object's 'model_name' field now holds our scan name.
            "scan_name": test_run.scan_name,
            # The model identifier is passed in as a separate argument.
            "model_identifier": model_identifier,
            "timestamp": test_run.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "overall_score": test_run.overall_score,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "pending_count": pending_count,
            "chart_data": chart_data,
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
