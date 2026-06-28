"""
YARA Engine for custom threat hunting.
Compiles YARA rules from the database and scans email contents and attachments.
"""
import logging
import yara
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import YaraRule

logger = logging.getLogger(__name__)


class YaraMatch(BaseModel):
    rule_name: str
    namespace: str
    tags: list[str]
    meta: dict
    strings_matched: list[str]


class YaraScanResult(BaseModel):
    matches: list[YaraMatch] = []
    total_matches: int = 0
    scan_error: str | None = None


class YaraEngine:
    def __init__(self):
        self.ruleset = None
        self.rules_loaded = 0

    async def reload_rules(self, db: AsyncSession):
        """Fetch all active rules from the database and compile them."""
        stmt = select(YaraRule).where(YaraRule.is_active == True)
        result = await db.execute(stmt)
        rules = result.scalars().all()

        if not rules:
            logger.info("No active YARA rules found. YARA engine disabled.")
            self.ruleset = None
            self.rules_loaded = 0
            return

        rule_sources = {}
        for rule in rules:
            # yara-python allows passing a dict of string sources
            rule_sources[rule.rule_name] = rule.rule_content

        try:
            self.ruleset = yara.compile(sources=rule_sources)
            self.rules_loaded = len(rules)
            logger.info(f"Successfully compiled {self.rules_loaded} YARA rules.")
        except yara.SyntaxError as e:
            logger.error(f"Syntax error compiling YARA rules: {e}")
            self.ruleset = None
            self.rules_loaded = 0
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.ruleset = None
            self.rules_loaded = 0

    def scan_data(self, data: bytes | str) -> YaraScanResult:
        """Scan raw bytes or text against the compiled ruleset."""
        if not self.ruleset:
            return YaraScanResult()

        if not data:
            return YaraScanResult()

        try:
            if isinstance(data, str):
                matches = self.ruleset.match(data=data.encode('utf-8', errors='ignore'))
            else:
                matches = self.ruleset.match(data=data)
            
            yara_matches = []
            for match in matches:
                # Extract matched strings safely (yara returns offset, matched_identifier, string_data)
                matched_strings = []
                for string_match in match.strings:
                    try:
                        # string_data is bytes
                        s_data = string_match[2].decode('utf-8', errors='ignore')
                        if s_data not in matched_strings:
                            matched_strings.append(s_data)
                    except:
                        pass

                yara_matches.append(YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=match.tags,
                    meta=match.meta,
                    strings_matched=matched_strings[:5]  # Limit to 5 samples
                ))
            
            return YaraScanResult(
                matches=yara_matches,
                total_matches=len(yara_matches)
            )

        except yara.TimeoutError:
            logger.warning("YARA scan timed out.")
            return YaraScanResult(scan_error="Scan timed out")
        except Exception as e:
            logger.error(f"Error during YARA scan: {e}")
            return YaraScanResult(scan_error=str(e))

    def analyze_email(self, body_text: str | None, body_html: str | None, attachments: list) -> YaraScanResult:
        """Scan the entire email context."""
        if not self.ruleset:
            return YaraScanResult()
            
        all_matches = []
        
        # Scan text body
        if body_text:
            res = self.scan_data(body_text)
            for m in res.matches:
                m.meta['context'] = 'body_text'
            all_matches.extend(res.matches)
            
        # Scan HTML body
        if body_html:
            res = self.scan_data(body_html)
            for m in res.matches:
                m.meta['context'] = 'body_html'
            all_matches.extend(res.matches)
            
        # Scan attachments
        for att in attachments:
            if hasattr(att, 'content') and att.content:
                res = self.scan_data(att.content)
                for m in res.matches:
                    m.meta['context'] = f'attachment:{att.filename}'
                all_matches.extend(res.matches)
                
        # Deduplicate matches by rule name and context
        unique_matches = []
        seen = set()
        for m in all_matches:
            key = f"{m.rule_name}_{m.meta.get('context', '')}"
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
                
        return YaraScanResult(
            matches=unique_matches,
            total_matches=len(unique_matches)
        )

# Global instance
yara_engine = YaraEngine()
