from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader


class ManifestRenderer:
    def __init__(self, template_dir: Path) -> None:
        self.env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=False)

    def render(self, scenario: dict, plan: dict, output_dir: Path, namespace: str = "sfc-demo") -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        catalog = {item["name"]: item for item in scenario.get("function_catalog", [])}

        primary_chain = plan.get("chains", [])[0]["functions"]
        function_defs = [catalog[name] for name in primary_chain if name in catalog]

        manifests = self.env.get_template("manifests.yaml.j2").render(
            namespace=namespace,
            functions=function_defs,
            chain_order=primary_chain,
        )
        deploy_readme = self.env.get_template("README-deploy.md.j2").render(
            namespace=namespace,
            chain_order=primary_chain,
        )

        manifests_path = output_dir / "manifests.yaml"
        readme_path = output_dir / "README-deploy.md"
        manifests_path.write_text(manifests, encoding="utf-8")
        readme_path.write_text(deploy_readme, encoding="utf-8")
        return manifests_path, readme_path
