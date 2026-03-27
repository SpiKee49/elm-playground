# Elm XSS Protection Middleware

A type-safe middleware library for protecting Elm applications against Cross-Site Scripting (XSS) attacks at the Elm-JavaScript boundary.

## Problem

Elm's built-in safety protects against XSS within the Elm ecosystem, but vulnerabilities can occur when:
- Sending data from Elm to JavaScript via ports
- JavaScript receives unsanitized user input and injects it into the DOM

This library provides a **centralized security layer** at the port boundary.

## Architecture

```
┌─────────────────────────────────────────┐
│           Elm Application               │
│                                         │
│  User Input → Model → Update            │
│                         ↓               │
│              Port.Middleware            │
│         (Security Policy Applied)       │
│                         ↓               │
│              Sanitized Data             │
└─────────────────┬───────────────────────┘
                  │
            Single Port
                  ↓
┌─────────────────────────────────────────┐
│            JavaScript                   │
│   Receives only sanitized data          │
└─────────────────────────────────────────┘
```

## Security Policies

The middleware offers **4 security policies** that developers must explicitly choose:

| Policy | Use Case | Protection |
|--------|----------|------------|
| `AllowTextOnly` | Plain text (usernames, comments) | Strips ALL HTML tags |
| `AllowSafeHtml` | Rich text editors | Strips dangerous tags (`<script>`) but keeps safe HTML (`<b>`, `<i>`) |
| `AllowUrl` | User-provided URLs | Blocks `javascript:` URLs |
| `Passthrough` | Trusted data (integers, booleans, system data) | No sanitization - **use with caution!** |

## Usage

### 1. Send Data with Policy

```elm
import Port.Middleware as Port

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        SaveUsername ->
            ( model
            , Port.sendString Port.AllowTextOnly model.username
            )
        
        SaveComment ->
            ( model
            , Port.sendString Port.AllowSafeHtml model.comment
            )
        
        SaveUrl ->
            ( model
            , Port.sendString Port.AllowUrl model.url
            )
        
        SaveCounter ->
            ( model
            , Port.send Port.Passthrough (Encode.int model.counter)
            )
```

### 2. Receive in JavaScript

```javascript
if (app.ports.sendToJS) {
    app.ports.sendToJS.subscribe(function(message) {
        const policy = message.policy;  // "text-only", "safe-html", "url", "passthrough"
        const data = message.data;      // Sanitized data
        
        console.log("Received:", policy, data);
        // Safe to use in DOM
    });
}
```

## Installation

1. Copy `Port.Middleware.elm` to your project
2. Import in your main module:

```elm
import Port.Middleware as Port
```

3. Compile your Elm code:

```bash
elm make src/Main.elm --output=elm.js
```

## Demo

The included demo showcases all 4 policies:

```bash
# Open index.html in browser
```

Try inputs like:
- `<script>alert('XSS')</script>` → Blocked by all policies
- `<b>Bold text</b>` → Allowed by `AllowSafeHtml`, stripped by `AllowTextOnly`
- `javascript:alert('XSS')` → Blocked by `AllowUrl`

## Key Benefits

- **Type-Safe**: Compiler forces you to choose a security policy
- **Centralized**: All data flows through one port
- **Explicit**: No hidden sanitization - developers see exactly what happens
- **Flexible**: Different policies for different data types
- **Zero Runtime**: Sanitization happens once at the boundary

## Important Notes

- **This protects the Elm → JS boundary** (output vector)
- For JS → Elm (input vector), validate JSON data with Elm decoders
- `Passthrough` policy bypasses all protection - only use for trusted data!
- For production, consider enhancing `AllowSafeHtml` with a proper HTML parser


## License

Part of diploma thesis: "Creating a library for protection against Cross-Site Script attacks in Elm environment"

---

**Author**: René Bukovina  
**Supervisor**: Ing. Ivan Kapustík  
**University**: Slovak University of Technology, FIIT