import os
import logging
import requests
import re
import sys
from getopt import getopt


class AghDownloader:
    _AGH_HOSTLISTS_REGISTRY_URL = 'https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filters.json'
    _log: logging.Logger
    _dir_path: str

    def __init__(self, filters_dir: str) -> None:
        self._log = logging.getLogger(self.__class__.__name__)
        self._dir_path = filters_dir
        os.mkdir(filters_dir)

    def download(self) -> None:
        filters_meta = self.load_filters_registry()
        for filter_meta in filters_meta:
            self.download_filter(f'{filter_meta["filterId"]}-{filter_meta["filterKey"]}', filter_meta["downloadUrl"])

    def load_filters_registry(self):
        self._log.info("Downloading filters registry")
        filter_registry_response = requests.get(self._AGH_HOSTLISTS_REGISTRY_URL)
        return filter_registry_response.json()["filters"]

    def download_filter(self, name: str, url: str):
        self._log.info("Downloading %s filter from %s", name, url)
        filter_response = requests.get(url)
        self._log.info("Saving %s filter", name)
        with open(f'{self._dir_path}/{name}', mode="wb") as file:
            file.write(filter_response.content)


class Agh2BlockyStat:
    _name: str
    _rules_count = 0
    _comment_count = 0
    _rules_wildcard_count = 0
    _rules_modified_count = 0
    _rules_wrong_syntax_count = 0
    _rules_block_count = 0
    _rules_allow_count = 0

    def __init__(self, name: str) -> None:
        self._name = name

    def __str__(self) -> str:
        result = f'Processed {self._rules_count} rules, {self._comment_count} commentaries; '
        result += f'wrote out {self._rules_block_count} block rules, {self._rules_allow_count} allow rules'
        if self._rules_wildcard_count or self._rules_modified_count or self._rules_wrong_syntax_count:
            result += "; "
            result += f'skipped {self._rules_wildcard_count} wildcard rules, '
            result += f'{self._rules_modified_count} modified rules, '
            result += f'{self._rules_wrong_syntax_count} rules with wrong syntax.'
        else:
            result += "."
        return result

    def get_rules_count(self):
        return self._rules_count

    def inc_rules_count(self):
        self._rules_count += 1

    def get_comment_count(self):
        return self._comment_count

    def inc_comment_count(self):
        self._comment_count += 1

    def get_rules_modified_count(self):
        return self._rules_modified_count

    def inc_rules_modified_count(self):
        self._rules_modified_count += 1

    def get_rules_wildcard_count(self):
        return self._rules_wildcard_count

    def inc_rules_wildcard_count(self):
        self._rules_wildcard_count += 1

    def get_rules_wrong_syntax_count(self):
        return self._rules_wrong_syntax_count

    def inc_rules_wrong_syntax_count(self):
        self._rules_wrong_syntax_count += 1

    def get_rules_block_count(self):
        return self._rules_block_count

    def inc_rules_block_count(self):
        self._rules_block_count += 1

    def get_rules_allow_count(self):
        return self._rules_allow_count

    def inc_rules_allow_count(self):
        self._rules_allow_count += 1


class Agh2Blocky:
    _BLOCK_LIST_EXT = '.blocky'
    _ALLOW_LIST_EXT = '.blocky.allow'
    _DOMAIN_PART_REGEX = r'[a-z0-9-\*\.]+'
    _IPV4_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    _BLOCKY_RULE_REGEX = r'((\*\.)?(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}'

    _log: logging.Logger
    _stat: Agh2BlockyStat
    _src_path: str
    _dst_block_path: str
    _dst_allow_path: str
    _domain_part_pattern: re.Pattern
    _ipv4_pattern: re.Pattern
    _blocky_rule_pattern: re.Pattern

    def __init__(self, src: str) -> None:
        self._log = logging.getLogger(self.__class__.__name__)
        self._stat = Agh2BlockyStat(src)
        self._src_path = src
        self._dst_block_path = src + self._BLOCK_LIST_EXT
        self._dst_allow_path = src + self._ALLOW_LIST_EXT

        self._domain_part_pattern = re.compile(self._DOMAIN_PART_REGEX)
        self._ipv4_pattern = re.compile(self._IPV4_REGEX)
        self._blocky_rule_pattern = re.compile(self._BLOCKY_RULE_REGEX)

    def convert(self):
        self._log.info("Converting %s", self._src_path)
        with (open(self._src_path, mode="r", encoding="utf8") as src_file,
              open(self._dst_block_path, mode="w", encoding="utf8") as dst_block_file,
              open(self._dst_allow_path, mode="w", encoding="utf8") as dst_allow_file):

            for line in src_file:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("!") or line.startswith("#"):
                    self._stat.inc_comment_count()
                    self._log.debug("Skipping commentary %s", line)
                    continue

                self._stat.inc_rules_count()
                line = self._remove_ipv4(line)

                domain_part_match = self._domain_part_pattern.search(line)
                if not domain_part_match:
                    self._stat.inc_rules_wrong_syntax_count()
                    self._log.debug("Skipping %s, domain part not found", line)
                    continue

                domain_part = domain_part_match.group()
                line_split = line.split(domain_part, 1)
                if len(line_split) != 2:
                    self._stat.inc_rules_wrong_syntax_count()
                    self._log.debug("Skipping %s, split error", line)
                    continue
                line_start = line_split[0]
                line_end = line_split[1]

                if line_end.startswith("^") or line_end.startswith("|"):
                    line_end = line_end[1:]

                # TODO: process $denyallow= https://adguard.com/kb/general/ad-filtering/create-own-filters/#denyallow-modifier
                if line_end.startswith("$"):
                    self._stat.inc_rules_modified_count()
                    self._log.debug("Skipping %s, modified rule", line)
                    continue

                domain_part = self._fix_wildcard(domain_part)

                if self._is_wildcard(domain_part):
                    self._stat.inc_rules_wildcard_count()
                    self._log.debug("Skipping wildcard %s", line)
                    continue

                allow_rule = self._is_allow_rule(line_start)
                if allow_rule:
                    line_start = line_start[2:]

                domain_part = self._convert_subdomain_rule(line_start, domain_part)

                blocky_rule_match = self._blocky_rule_pattern.fullmatch(domain_part)
                if not blocky_rule_match:
                    self._stat.inc_rules_wrong_syntax_count()
                    self._log.debug("Skipping %s, doesn't match Blocky rule", domain_part)
                    continue

                line_out = f'{domain_part}\n'
                if allow_rule:
                    self._stat.inc_rules_allow_count()
                    dst_allow_file.write(line_out)
                else:
                    self._stat.inc_rules_block_count()
                    dst_block_file.write(line_out)

        self._delete_empty_files()
        self._log.info(self._stat)

    def _remove_ipv4(self, line: str) -> str:
        ipv4_match = self._ipv4_pattern.search(line)
        if ipv4_match:
            ipv4 = ipv4_match.group()
            line = line.replace(ipv4, "").strip()
        return line

    def _fix_wildcard(self, domain_part: str) -> str:
        if domain_part.startswith("."):
            domain_part = f'*{domain_part}'
        if domain_part.endswith("."):
            domain_part = f'{domain_part}*'
        return domain_part

    def _is_wildcard(self, domain_part: str) -> bool:
        try:
            domain_part.index("*", 1)
        except ValueError:
            return False
        return True

    def _is_allow_rule(self, rule_start: str) -> bool:
        return rule_start.startswith("@@")

    def _is_subdomain_rule(self, rule_start: str) -> bool:
        return rule_start.startswith("||")

    def _convert_subdomain_rule(self, rule_start: str, domain_part: str) -> str:
        if self._is_subdomain_rule(rule_start) and not domain_part.startswith("*"):
            domain_part = f'*.{domain_part}'
        return domain_part

    def _delete_empty_files(self) -> None:
        if os.path.getsize(self._dst_block_path) == 0:
            os.remove(self._dst_block_path)

        if os.path.getsize(self._dst_allow_path) == 0:
            os.remove(self._dst_allow_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("agh2blocky")

    # filters-dir - directory to store filters
    opts, args = getopt(sys.argv[1:], "", [
        "filters-dir=",
    ])
    params = {opt[0].replace('-', '', 2): opt[1] for opt in opts}
    filters_dir = params.get('filters-dir', 'filters')

    if "download" in args:
        AghDownloader(filters_dir).download()

    if "convert" in args:
        for filename in os.scandir(filters_dir):
            if filename.is_file():
                Agh2Blocky(filename.path).convert()

    log.info("Done")
