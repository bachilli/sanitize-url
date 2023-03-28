<?php

$sanitizeUrl = new \Bachilli\SanitizeUrl\SanitizeUrl();

it('does not alter http URLs with alphanumeric characters', function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('http://example.com/path/to:something'))->toBe(
        'http://example.com/path/to:something'
    );
});

it("does not alter http URLs with ports with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('http://example.com:4567/path/to:something'))->toBe(
        "http://example.com:4567/path/to:something"
    );
});

it("does not alter https URLs with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('https://example.com'))->toBe("https://example.com");
});

it("does not alter https URLs with ports with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('https://example.com:4567/path/to:something'))->toBe(
        "https://example.com:4567/path/to:something"
    );
});

it("does not alter relative-path reference URLs with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('./path/to/my.json'))->toBe("./path/to/my.json");
});

it("does not alter absolute-path reference URLs with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('/path/to/my.json'))->toBe("/path/to/my.json");
});

it("does not alter protocol-less network-path URLs with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('//google.com/robots.txt'))->toBe(
        "//google.com/robots.txt"
    );
});

it("does not alter protocol-less URLs with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('www.example.com'))->toBe("www.example.com");
});

it("does not alter deep-link urls with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('com.braintreepayments.demo://example'))->toBe(
        "com.braintreepayments.demo://example"
    );
});

it("does not alter mailto urls with alphanumeric characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('mailto:test@example.com?subject=hello+world'))->toBe(
        "mailto:test@example.com?subject=hello+world"
    );
});

it("does not alter urls with accented characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('www.example.com/with-áccêntš'))->toBe(
        "www.example.com/with-áccêntš"
    );
});

it("does not strip harmless unicode characters", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl('www.example.com/лот.рфшишкиü–'))->toBe(
        "www.example.com/лот.рфшишкиü–"
    );
});

it("strips out ctrl chars", function () use ($sanitizeUrl) {
    expect(
        $sanitizeUrl->sanitizeUrl('www.example.com/\u200D\u0000\u001F\x00\x1F\uFEFFfoo')
    )->toBe("www.example.com/foo");
});

it("replaces blank urls with about:blank", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(''))->toBe("about:blank");
});

it("replaces null values with about:blank", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(null))->toBe("about:blank");
});

it("removes whitespace from urls", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl("   http://example.com/path/to:something    "))->toBe(
        "http://example.com/path/to:something"
    );
});

it("removes newline entities from urls", function () use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl("https://example.com&NewLine;&NewLine;/something"))->toBe(
        "https://example.com/something"
    );
});

//it("decodes html entities", () => {
//    // all these decode to javascript:alert('xss');
//    const attackVectors = [
//        "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
//        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;",
//        "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
//        "jav&#x09;ascript:alert('XSS');",
//        " &#14; javascript:alert('XSS');",
//        "javasc&Tab;ript: alert('XSS');",
//    ];
//
//    attackVectors.forEach((vector) => {
//        expect(sanitizeUrl(vector)).toBe("about:blank");
//    });
//
//    // https://example.com/javascript:alert('XSS')
//    // since the javascript is the url path, and not the protocol,
//    // this url is technically sanitized
//    expect(
//        sanitizeUrl(
//            "&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041"
//        )
//    ).toBe("https://example.com/javascript:alert('XSS')");
//  });

it('decodes html entities', function (string $vector) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl($vector))->toBe('about:blank');
})->with([
    '&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;',
    '&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29',
    'jav&#x09;ascript:alert(\'XSS\');',
    ' &#14; javascript:alert(\'XSS\');',
    'javasc&Tab;ript: alert(\'XSS\');',
])->expect($sanitizeUrl->sanitizeUrl('&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'))
    ->toBe('https://example.com/javascript:alert(\'XSS\')');

it('replaces ${protocol} urls with about:blank', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl($protocol . ':alert(document.domain)'))
        ->toBe('about:blank');
})->with(["javascript", "data", "vbscript"]);

it('allows ${protocol} urls that start with a letter prefix', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(sprintf("not_%s:alert(document.domain)", $protocol)))
        ->toBe(sprintf("not_%s:alert(document.domain)", $protocol));
})->with(["javascript", "data", "vbscript"]);

it('disallows ${protocol} urls that start with non-\w characters as a suffix for the protocol', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        sprintf("&!*%s:alert(document.domain)", $protocol)
    ))->toBe('about:blank');
})->with(["javascript", "data", "vbscript"]);

it('disallows ${protocol} urls that use &colon; for the colon portion of the url', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        sprintf("%s&colon;alert(document.domain)", $protocol)
    ))->toBe('about:blank');
    expect($sanitizeUrl->sanitizeUrl(
        sprintf("%s&COLON;alert(document.domain)", $protocol)
    ))->toBe('about:blank');
})->with(["javascript", "data", "vbscript"]);

it('disregards capitalization for ${protocol} urls', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        sprintf("%s:alert(document.domain)", $protocol)
    ))->toBe('about:blank');
})->with(["JaVaScRipT", "DaTa", "VbScRiPt"]);

it('ignores invisible ctrl characters in ${protocol} urls', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        urldecode(
            sprintf("%s:alert(document.domain)", $protocol)
        )
    ))->toBe('about:blank');
})->with(
    [
        "ja%EF%BB%BF%EF%BB%BFv%e2%80%8bascript",
        "da%EF%BB%BF%EF%BB%BFt%e2%80%8ba",
        "vb%EF%BB%BF%EF%BB%BFs%e2%80%8bcript"
    ]
);

it('replaces ${protocol} urls with about:blank when url begins with %20', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        urldecode(
            "%20%20%20%20$protocol:alert(document.domain)"
        )
    ))->toBe('about:blank');
})->with(["javascript", "data", "vbscript"]);

it('replaces ${protocol} urls with about:blank when ${protocol} url begins with spaces', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        "    $protocol:alert(document.domain)"
    ))->toBe('about:blank');
})->with(["javascript", "data", "vbscript"]);

it('does not replace ${protocol}: if it is not in the scheme of the URL', function (string $protocol) use ($sanitizeUrl) {
    expect($sanitizeUrl->sanitizeUrl(
        "http://example.com#$protocol:foo"
    ))->toBe("http://example.com#$protocol:foo");
})->with(["javascript", "data", "vbscript"]);