module Tests exposing
    ( TestCase
    , TestResult
    , allTests
    , runAllTests
    , runTest
    , passCount
    , failCount
    )

{-|
Tests — Runtime test suite for the Port.Middleware sanitization library.

Because this is a browser-based Elm application (not elm-explorations/test),
tests are run at runtime and their results rendered in the demo UI. Each test
case specifies:

  - The security policy under test
  - A raw input string (often a known XSS payload)
  - Strings that must NOT appear in the sanitized output  (shouldBlock)
  - Strings that MUST appear in the sanitized output      (shouldPass)

A test PASSES when all shouldBlock strings are absent AND all shouldPass
strings are present in the sanitized output.

shouldBlock checks are case-insensitive so that e.g. "<SCRIPT" and "<script"
are treated equivalently — the sanitizer must remove the construct in any case.
shouldPass checks are case-sensitive since expected output is exact.
-}

import Port.Middleware as Middleware exposing (SecurityPolicy(..), sanitize)


-- TYPES

type alias TestCase =
    { description    : String
    , policy         : SecurityPolicy
    , category       : String
    , input          : String
    , shouldBlock    : List String   -- must NOT appear in output (case-insensitive)
    , shouldPass     : List String   -- MUST appear in output (case-sensitive)
    }


type alias TestResult =
    { testCase  : TestCase
    , output    : String
    , passed    : Bool
    , failures  : List String
    }


-- RUNNER

runTest : TestCase -> TestResult
runTest tc =
    let
        output       = sanitize tc.policy tc.input
        outputLower  = String.toLower output

        blockViolations =
            tc.shouldBlock
                |> List.filter (\s -> String.contains (String.toLower s) outputLower)
                |> List.map (\s -> "Still contains: \"" ++ s ++ "\"")

        passViolations =
            tc.shouldPass
                |> List.filter (\s -> not (String.contains s output))
                |> List.map (\s -> "Missing expected: \"" ++ s ++ "\"")

        failures = blockViolations ++ passViolations
    in
    { testCase = tc
    , output   = output
    , passed   = List.isEmpty failures
    , failures = failures
    }


runAllTests : List TestResult
runAllTests =
    List.map runTest allTests


passCount : List TestResult -> Int
passCount =
    List.length << List.filter .passed


failCount : List TestResult -> Int
failCount results =
    List.length results - passCount results


-- TEST SUITE

allTests : List TestCase
allTests =
    allowTextOnlyTests
        ++ allowSafeHtmlTests
        ++ allowUrlTests


-- ─── AllowTextOnly ────────────────────────────────────────────────────────────
-- Policy intent: strip ALL HTML tags; HTML-escape remaining text.
-- Even safe-looking tags are removed — output is pure plain text.

allowTextOnlyTests : List TestCase
allowTextOnlyTests =
    [ { description   = "Strips basic <script> tag"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<script>alert('xss')</script>"
      , shouldBlock   = [ "<script" ]
      , shouldPass    = []
      }
    , { description   = "Strips <img onerror=> tag"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<img src=x onerror=alert(1)>"
      , shouldBlock   = [ "<img", "onerror" ]
      , shouldPass    = []
      }
    , { description   = "Strips safe <b> tag (no tags allowed)"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<b>bold</b>"
      , shouldBlock   = [ "<b>" ]
      , shouldPass    = [ "bold" ]
      }
    , { description   = "Escapes & to &amp;"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "cats & dogs"
      , shouldBlock   = []
      , shouldPass    = [ "cats &amp; dogs" ]
      }
    , { description   = "Escapes < to &lt; and > to &gt;"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "1 < 2 > 0"
      , shouldBlock   = []
      , shouldPass    = [ "&lt;", "&gt;" ]
      }
    , { description   = "Escapes \" to &quot;"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "say \"hello\""
      , shouldBlock   = []
      , shouldPass    = [ "&quot;" ]
      }
    , { description   = "Obfuscation: tag with embedded newline <scr\\nipt>"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<scr\nipt>alert(1)</scr\nipt>"
      , shouldBlock   = [ "<scr" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: null byte inside tag"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<scr\u{0000}ipt>alert(1)</scr\u{0000}ipt>"
      , shouldBlock   = [ "alert" ]
      , shouldPass    = []
      }
    , { description   = "Preserves plain text unchanged"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "Hello, World!"
      , shouldBlock   = []
      , shouldPass    = [ "Hello, World!" ]
      }
    , { description   = "Strips double-bracket trick <<script>"
      , policy        = AllowTextOnly
      , category      = "AllowTextOnly"
      , input         = "<<script>alert(1)<</script>"
      , shouldBlock   = [ "<script", "alert" ]
      , shouldPass    = []
      }
    ]


-- ─── AllowSafeHtml ────────────────────────────────────────────────────────────
-- Policy intent: allow a safe subset of HTML (bold, italic, spans…);
-- strip <script>, dangerous tags, event handlers, and javascript: in attrs.

allowSafeHtmlTests : List TestCase
allowSafeHtmlTests =
    [ { description   = "Strips <script> block, keeps <b>"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<b>bold</b><script>alert('xss')</script>"
      , shouldBlock   = [ "<script" ]
      , shouldPass    = [ "<b>" ]
      }
    , { description   = "Strips uppercase <SCRIPT> (case obfuscation)"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<SCRIPT>alert(1)</SCRIPT>"
      , shouldBlock   = [ "script" ]
      , shouldPass    = []
      }
    , { description   = "Strips multiline <script> block"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<script\n  type=\"text/javascript\">\nalert(1)\n</script>"
      , shouldBlock   = [ "script", "alert" ]
      , shouldPass    = []
      }
    , { description   = "Strips onerror= event handler on <img>"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<img src=x onerror=alert(1)>"
      , shouldBlock   = [ "onerror" ]
      , shouldPass    = []
      }
    , { description   = "Strips mixed-case onMouseOver= (case obfuscation)"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<div onMouseOver=alert(1)>hover</div>"
      , shouldBlock   = [ "onmouseover" ]
      , shouldPass    = []
      }
    , { description   = "Strips onclick with space before = (whitespace obfuscation)"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<div onclick =alert(1)>click</div>"
      , shouldBlock   = [ "onclick" ]
      , shouldPass    = []
      }
    , { description   = "Strips <iframe> tag"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<iframe src=\"https://evil.com\"></iframe>"
      , shouldBlock   = [ "<iframe" ]
      , shouldPass    = []
      }
    , { description   = "Strips <svg onload=> block"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<svg onload=\"alert(1)\"></svg>"
      , shouldBlock   = [ "<svg", "onload" ]
      , shouldPass    = []
      }
    , { description   = "Strips javascript: in href attribute, keeps <a> element"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<a href=\"javascript:alert(1)\">click</a>"
      , shouldBlock   = [ "javascript:" ]
        -- The tokenizer drops the invalid href but preserves the <a> tag;
        -- there is no trailing space when the attr list is empty.
      , shouldPass    = [ "<a>" ]
      }
    , { description   = "Strips <object data=> tag"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<object data=\"https://evil.com/payload.swf\"></object>"
      , shouldBlock   = [ "<object" ]
      , shouldPass    = []
      }
    , { description   = "Strips <meta http-equiv=refresh>"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.com\">"
      , shouldBlock   = [ "<meta" ]
      , shouldPass    = []
      }
    , { description   = "Preserves safe <b>, <i>, <p> tags"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<p>A <b>bold</b> and <i>italic</i> paragraph.</p>"
      , shouldBlock   = []
      , shouldPass    = [ "<b>", "<i>", "<p>" ]
      }
    , { description   = "Strips <embed> tag"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<embed src=\"https://evil.com/plugin.swf\">"
      , shouldBlock   = [ "<embed" ]
      , shouldPass    = []
      }

    -- ── Tokenizer-specific tests (would defeat regex but not the parser) ───────

    , { description   = "Parser: drops on* attr, preserves safe attrs on same tag"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<span class=\"note\" onclick=\"alert(1)\" title=\"ok\">text</span>"
      , shouldBlock   = [ "onclick" ]
      , shouldPass    = [ "class=\"note\"", "title=\"ok\"", "text" ]
      }
    , { description   = "Parser: javascript: href with surrounding whitespace"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<a href=\" javascript:alert(1) \">x</a>"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = [ "<a>" ]
      }
    , { description   = "Parser: data: src on img is blocked"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<img src=\"data:image/png;base64,abc\" alt=\"x\">"
      , shouldBlock   = [ "data:" ]
      , shouldPass    = [ "alt=\"x\"" ]
      }
    , { description   = "Parser: nested <svg> inside safe HTML drops both svg blocks"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<p>hello</p><svg><svg onload=\"alert(1)\"></svg></svg><p>world</p>"
      , shouldBlock   = [ "<svg", "onload", "alert" ]
      , shouldPass    = [ "<p>hello</p>", "<p>world</p>" ]
      }
    , { description   = "Parser: unknown element tag is dropped but text child is kept"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<custom-widget>safe text</custom-widget>"
      , shouldBlock   = [ "<custom-widget" ]
      , shouldPass    = [ "safe text" ]
      }
    , { description   = "Parser: safe https: src on img is kept"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<img src=\"https://example.com/photo.jpg\" alt=\"photo\">"
      , shouldBlock   = []
      , shouldPass    = [ "src=\"https://example.com/photo.jpg\"", "alt=\"photo\"" ]
      }
    ]


-- ─── AllowUrl ─────────────────────────────────────────────────────────────────
-- Policy intent: allow safe http/https/relative URLs; reject dangerous schemes.
-- Output is the original string (if safe) or "" (if blocked).

allowUrlTests : List TestCase
allowUrlTests =
    [ { description   = "Blocks javascript: scheme"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "javascript:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Blocks data: scheme"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "data:text/html,<script>alert(1)</script>"
      , shouldBlock   = [ "data:" ]
      , shouldPass    = []
      }
    , { description   = "Blocks vbscript: scheme"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "vbscript:msgbox(1)"
      , shouldBlock   = [ "vbscript" ]
      , shouldPass    = []
      }
    , { description   = "Blocks JAVASCRIPT: (uppercase obfuscation)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "JAVASCRIPT:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: java\\tscript: (tab-separated)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "java\tscript:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: java\\nscript: (newline-split)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "java\nscript:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: java\\rscript: (CR-split)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "java\rscript:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: java\\u{0000}script: (null byte)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "java\u{0000}script:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: &#106;avascript: (entity-encoded j)"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "&#106;avascript:alert(1)"
      , shouldBlock   = [ "javascript", "&#106;" ]
      , shouldPass    = []
      }
    , { description   = "Obfuscation: leading whitespace before javascript:"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "   javascript:alert(1)"
      , shouldBlock   = [ "javascript" ]
      , shouldPass    = []
      }
    , { description   = "Allows https:// URL"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "https://example.com/page"
      , shouldBlock   = []
      , shouldPass    = [ "https://example.com/page" ]
      }
    , { description   = "Allows relative path URL"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "/images/photo.jpg"
      , shouldBlock   = []
      , shouldPass    = [ "/images/photo.jpg" ]
      }
    , { description   = "Allows mailto: URL"
      , policy        = AllowUrl
      , category      = "AllowUrl"
      , input         = "mailto:user@example.com"
      , shouldBlock   = []
      , shouldPass    = [ "mailto:user@example.com" ]
      }
    ]
