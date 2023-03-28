<?php

namespace Bachilli\SanitizeUrl;

class SanitizeUrl
{
    const INVALID_PROTOCOL_REGEX = '/^([^\w]*)(javascript|data|vbscript)/im';
    const HTML_ENTITIES_REGEX = '/&#(\w+)(^\w|;)?/';
    const HTML_CTRL_ENTITY_REGEX = '/&(newline|tab);/i';
    const HTML_CTRL_ENTITY_REGEX2 = '/\s+/S';
    const CTRL_CHARACTERS_REGEX = '/\\\\u([0-9A-F]{0,4})|\\\\x[0-9A-F]{0,2}/';
    const URL_SCHEME_REGEX = '/^.+(:|&colon;)/im';
    const RELATIVE_FIRST_CHARACTERS = [".", "/"];

    public function sanitizeUrl(?string $url = null)
    {
        $url = $this->decodeHtmlCharacters($url);
        $url = preg_replace(self::HTML_CTRL_ENTITY_REGEX, '', $url);
        $url = preg_replace(self::HTML_CTRL_ENTITY_REGEX2, '', $url);
        $url = preg_replace(self::CTRL_CHARACTERS_REGEX, '', $url);
        $url = trim($url);

        if (!$url) {
            return 'about:blank';
        }

        if ($this->isRelativeUrlWithoutProtocol($url)) {
            return $url;
        }

        preg_match(self::URL_SCHEME_REGEX, $url, $urlSchemeParseResults);

        if (!$urlSchemeParseResults) {
            return $url;
        }

        if (preg_grep(self::INVALID_PROTOCOL_REGEX, $urlSchemeParseResults)) {
            return 'about:blank';
        }

        return $url;
    }

    protected function isRelativeUrlWithoutProtocol(string $url)
    {
        return in_array(
            substr($url, 0, 1),
            self::RELATIVE_FIRST_CHARACTERS
        );
    }

    protected function decodeHtmlCharacters(?string $url = null)
    {
        $nMatches = preg_match_all(
            self::HTML_ENTITIES_REGEX,
            $url,
            $matches
        );

        $search = [];
        $replace = [];

        if ($nMatches > 0) {
            $search = $matches[0];

            foreach ($matches[1] as $key => $charCode) {
                if (strtolower(substr($charCode, 0, 1)) === 'x') {
                    $charCode = hexdec('0'.$charCode);
                }

                $replace[] = chr($charCode);
            }
        }

        return str_replace($search, $replace, $url);
    }
}
