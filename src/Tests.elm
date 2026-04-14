module Tests exposing
    ( TestCase
    , TestResult
    , ComparisonPayload
    , allTests
    , comparisonPayloads
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
    , { description   = "Strips javascript: in href attribute"
      , policy        = AllowSafeHtml
      , category      = "AllowSafeHtml"
      , input         = "<a href=\"javascript:alert(1)\">click</a>"
      , shouldBlock   = [ "javascript:" ]
      , shouldPass    = [ "<a " ]
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


-- ─── COMPARISON PAYLOADS ──────────────────────────────────────────────────────
-- A curated set of ~85 XSS payloads used to compare the Elm sanitizer against
-- DOMPurify side-by-side. Unlike TestCase, these carry no expected assertions —
-- the comparison view simply shows what each library produces for the same input.
--
-- Sources: OWASP XSS filter evasion cheat sheet, PortSwigger XSS cheat sheet,
-- HTML5 Security Cheat Sheet, known mXSS research vectors.

type alias ComparisonPayload =
    { id       : String
    , category : String
    , input    : String
    }


comparisonPayloads : List ComparisonPayload
comparisonPayloads =
    scriptTagPayloads
        ++ eventHandlerPayloads
        ++ jsUrlPayloads
        ++ dangerousTagPayloads
        ++ cssVectorPayloads
        ++ mxssPayloads
        ++ encodingPayloads
        ++ safePayloads


-- ─── Script Tags ──────────────────────────────────────────────────────────────

scriptTagPayloads : List ComparisonPayload
scriptTagPayloads =
    [ { id = "s1",  category = "Script Tags", input = "<script>alert(1)</script>" }
    , { id = "s2",  category = "Script Tags", input = "<SCRIPT>alert(1)</SCRIPT>" }
    , { id = "s3",  category = "Script Tags", input = "<Script>alert(1)</Script>" }
    , { id = "s4",  category = "Script Tags", input = "</script><script>alert(1)</script>" }
    , { id = "s5",  category = "Script Tags", input = "<script type=\"text/javascript\">alert(1)</script>" }
    , { id = "s6",  category = "Script Tags", input = "<script\n>alert(1)</script>" }
    , { id = "s7",  category = "Script Tags", input = "<script\n  type=\"text/javascript\">\nalert(1)\n</script>" }
    , { id = "s8",  category = "Script Tags", input = "<scr<script>ipt>alert(1)</scr</script>ipt>" }
    , { id = "s9",  category = "Script Tags", input = "<!--<script>alert(1)</script>-->" }
    , { id = "s10", category = "Script Tags", input = "<script>alert(String.fromCharCode(88,83,83))</script>" }
    , { id = "s11", category = "Script Tags", input = "<script src=\"//evil.com/xss.js\"></script>" }
    , { id = "s12", category = "Script Tags", input = "<script>document.cookie</script>" }
    , { id = "s13", category = "Script Tags", input = "<script>eval(atob('YWxlcnQoMSk='))</script>" }
    , { id = "s14", category = "Script Tags", input = "<<script>alert(1)<</script>" }
    , { id = "s15", category = "Script Tags", input = "<scr\u{0000}ipt>alert(1)</scr\u{0000}ipt>" }
    ]


-- ─── Event Handlers ───────────────────────────────────────────────────────────

eventHandlerPayloads : List ComparisonPayload
eventHandlerPayloads =
    [ { id = "e1",  category = "Event Handlers", input = "<img src=x onerror=alert(1)>" }
    , { id = "e2",  category = "Event Handlers", input = "<img src=x onerror=\"alert(1)\">" }
    , { id = "e3",  category = "Event Handlers", input = "<body onload=alert(1)>" }
    , { id = "e4",  category = "Event Handlers", input = "<input onfocus=alert(1) autofocus>" }
    , { id = "e5",  category = "Event Handlers", input = "<select onchange=alert(1)><option>a</option></select>" }
    , { id = "e6",  category = "Event Handlers", input = "<details ontoggle=alert(1) open>x</details>" }
    , { id = "e7",  category = "Event Handlers", input = "<video><source onerror=alert(1)></video>" }
    , { id = "e8",  category = "Event Handlers", input = "<audio src=x onerror=alert(1)>" }
    , { id = "e9",  category = "Event Handlers", input = "<div onmouseover=alert(1)>hover</div>" }
    , { id = "e10", category = "Event Handlers", input = "<a onclick=alert(1)>click</a>" }
    , { id = "e11", category = "Event Handlers", input = "<img src=x ONERROR=alert(1)>" }
    , { id = "e12", category = "Event Handlers", input = "<div onclick =alert(1)>click</div>" }
    , { id = "e13", category = "Event Handlers", input = "<p onmouseenter=alert(1)>text</p>" }
    , { id = "e14", category = "Event Handlers", input = "<textarea onblur=alert(1) autofocus></textarea>" }
    , { id = "e15", category = "Event Handlers", input = "<svg onload=alert(1)>test</svg>" }
    ]


-- ─── JavaScript URLs ──────────────────────────────────────────────────────────

jsUrlPayloads : List ComparisonPayload
jsUrlPayloads =
    [ { id = "j1",  category = "JavaScript URLs", input = "<a href=\"javascript:alert(1)\">click</a>" }
    , { id = "j2",  category = "JavaScript URLs", input = "<a href=\"JAVASCRIPT:alert(1)\">click</a>" }
    , { id = "j3",  category = "JavaScript URLs", input = "<a href=\"JaVaScRiPt:alert(1)\">click</a>" }
    , { id = "j4",  category = "JavaScript URLs", input = "<a href=\"&#106;avascript:alert(1)\">click</a>" }
    , { id = "j5",  category = "JavaScript URLs", input = "<a href=\"&#x6A;avascript:alert(1)\">click</a>" }
    , { id = "j6",  category = "JavaScript URLs", input = "<a href=\" javascript:alert(1)\">click</a>" }
    , { id = "j7",  category = "JavaScript URLs", input = "<img src=\"javascript:alert(1)\">" }
    , { id = "j8",  category = "JavaScript URLs", input = "<form action=\"javascript:alert(1)\">" }
    , { id = "j9",  category = "JavaScript URLs", input = "<a href=\"vbscript:msgbox(1)\">click</a>" }
    , { id = "j10", category = "JavaScript URLs", input = "<a href=\"data:text/html,<script>alert(1)</script>\">click</a>" }
    , { id = "j11", category = "JavaScript URLs", input = "<iframe src=\"javascript:alert(1)\">" }
    , { id = "j12", category = "JavaScript URLs", input = "<a href=\"java\tscript:alert(1)\">click</a>" }
    , { id = "j13", category = "JavaScript URLs", input = "<a href=\"java\nscript:alert(1)\">click</a>" }
    , { id = "j14", category = "JavaScript URLs", input = "<object data=\"javascript:alert(1)\">" }
    , { id = "j15", category = "JavaScript URLs", input = "<a href=\"javascript\u{0000}:alert(1)\">click</a>" }
    ]


-- ─── Dangerous Tags ───────────────────────────────────────────────────────────

dangerousTagPayloads : List ComparisonPayload
dangerousTagPayloads =
    [ { id = "d1",  category = "Dangerous Tags", input = "<iframe src=\"https://evil.com\"></iframe>" }
    , { id = "d2",  category = "Dangerous Tags", input = "<object data=\"https://evil.com/payload.swf\"></object>" }
    , { id = "d3",  category = "Dangerous Tags", input = "<embed src=\"https://evil.com/plugin.swf\">" }
    , { id = "d4",  category = "Dangerous Tags", input = "<base href=\"https://evil.com/\">" }
    , { id = "d5",  category = "Dangerous Tags", input = "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.com\">" }
    , { id = "d6",  category = "Dangerous Tags", input = "<link rel=\"stylesheet\" href=\"https://evil.com/evil.css\">" }
    , { id = "d7",  category = "Dangerous Tags", input = "<form action=\"https://evil.com/steal\" method=\"post\">" }
    , { id = "d8",  category = "Dangerous Tags", input = "<IFRAME src=\"https://evil.com\">" }
    , { id = "d9",  category = "Dangerous Tags", input = "<frame src=\"https://evil.com\">" }
    , { id = "d10", category = "Dangerous Tags", input = "<frameset><frame src=\"https://evil.com\"></frameset>" }
    ]


-- ─── CSS Vectors ──────────────────────────────────────────────────────────────

cssVectorPayloads : List ComparisonPayload
cssVectorPayloads =
    [ { id = "c1", category = "CSS Vectors", input = "<style>body{background:url(javascript:alert(1))}</style>" }
    , { id = "c2", category = "CSS Vectors", input = "<div style=\"background:url(javascript:alert(1))\">x</div>" }
    , { id = "c3", category = "CSS Vectors", input = "<style>*{x:expression(alert(1))}</style>" }
    , { id = "c4", category = "CSS Vectors", input = "<style>@import 'https://evil.com/evil.css'</style>" }
    , { id = "c5", category = "CSS Vectors", input = "<div style=\"width:expression(alert(1))\">" }
    ]


-- ─── mXSS / HTML5 ────────────────────────────────────────────────────────────
-- Mutation-based XSS: payloads that may survive regex sanitization but are
-- re-parsed by the browser into executable form. DOMPurify uses the DOM parser
-- internally and re-serializes, making it resistant to many mXSS vectors.

mxssPayloads : List ComparisonPayload
mxssPayloads =
    [ { id = "m1",  category = "mXSS / HTML5", input = "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">" }
    , { id = "m2",  category = "mXSS / HTML5", input = "<!-- --!><img src=x onerror=alert(1)>" }
    , { id = "m3",  category = "mXSS / HTML5", input = "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>" }
    , { id = "m4",  category = "mXSS / HTML5", input = "<xmp><script>alert(1)</script></xmp>" }
    , { id = "m5",  category = "mXSS / HTML5", input = "<plaintext><img src=x onerror=alert(1)>" }
    , { id = "m6",  category = "mXSS / HTML5", input = "<p id=\"</p><img src=x onerror=alert(1)>\">test</p>" }
    , { id = "m7",  category = "mXSS / HTML5", input = "<style><!--</style><img src=x onerror=alert(1)>-->" }
    , { id = "m8",  category = "mXSS / HTML5", input = "<table><td><a href=\"javascript:alert(1)\">click</a></td></table>" }
    , { id = "m9",  category = "mXSS / HTML5", input = "<svg><animate onbegin=alert(1) attributeName=x dur=1s>" }
    , { id = "m10", category = "mXSS / HTML5", input = "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">" }
    ]


-- ─── Encoding Tricks ──────────────────────────────────────────────────────────

encodingPayloads : List ComparisonPayload
encodingPayloads =
    [ { id = "enc1",  category = "Encoding Tricks", input = "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>" }
    , { id = "enc2",  category = "Encoding Tricks", input = "&lt;script&gt;alert(1)&lt;/script&gt;" }
    , { id = "enc3",  category = "Encoding Tricks", input = "<IMG SRC=x ONERROR=alert(1)>" }
    , { id = "enc4",  category = "Encoding Tricks", input = "<a href=\"java&#9;script:alert(1)\">click</a>" }
    , { id = "enc5",  category = "Encoding Tricks", input = "<a href=\"java&#10;script:alert(1)\">click</a>" }
    , { id = "enc6",  category = "Encoding Tricks", input = "<a href=\"java&#13;script:alert(1)\">click</a>" }
    , { id = "enc7",  category = "Encoding Tricks", input = "<a href=\"&#0000106;avascript:alert(1)\">click</a>" }
    , { id = "enc8",  category = "Encoding Tricks", input = "<img src=\"x\" onerror=\"javascript:alert(1)\">" }
    , { id = "enc9",  category = "Encoding Tricks", input = "<a href=\"\u{0000}javascript:alert(1)\">click</a>" }
    , { id = "enc10", category = "Encoding Tricks", input = "<iframe src=\"\u{0000}javascript:alert(1)\">" }
    ]


-- ─── Safe Inputs ──────────────────────────────────────────────────────────────
-- Benign inputs that should pass through both sanitizers largely unchanged.
-- Useful for checking that neither library over-blocks legitimate content.

safePayloads : List ComparisonPayload
safePayloads =
    [ { id = "safe1", category = "Safe Inputs", input = "<b>bold text</b>" }
    , { id = "safe2", category = "Safe Inputs", input = "<p>Hello <em>world</em>!</p>" }
    , { id = "safe3", category = "Safe Inputs", input = "<span class=\"highlight\">text</span>" }
    , { id = "safe4", category = "Safe Inputs", input = "This is plain text with no HTML." }
    , { id = "safe5", category = "Safe Inputs", input = "<a href=\"https://example.com\">Link</a>" }
    ]
