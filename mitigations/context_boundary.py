import re

class ContextBoundaryBoxer:
    @staticmethod
    def box(raw_text: str, source: str = "external_tool") -> str:
        safe_text = raw_text.replace("<untrusted_content>", "&lt;untrusted_content&gt;")
        safe_text = safe_text.replace("</untrusted_content>", "&lt;/untrusted_content&gt;")
        return f"<untrusted_content source='{source}'>\n{safe_text.strip()}\n</untrusted_content>"
