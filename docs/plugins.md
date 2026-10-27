# Plugins

`"plugins": ["my_module:MyHooks"]` in the config loads an object whose optional methods are called at these points:

| Hook | When | Arguments |
|---|---|---|
| `before_protect(ctx)` | after classification, before pseudonymisation | `ctx.messages`, `ctx.data_class`, `ctx.candidates` are set and may be changed |
| `before_call(ctx, backend, model)` | right before an upstream call | |
| `after_call(ctx, result)` | after a successful upstream call, before restoration | `result.message`, `result.finish`, token counts |
| `after_restore(ctx)` | after values are restored | `ctx.result.message` is final; `ctx.rec` is the audit line |

`ctx.rec` is the audit record; a plugin may add fields to it (no text, please). Exceptions in a plugin fail the request
with 500 and are logged.

Example: refuse any cloud route for a project.

```python
class OnlyLocalForBooks:
    def before_protect(self, ctx):
        if ctx.project == "books":
            ctx.candidates = [c for c in ctx.candidates if c[0] == "llama"] or ctx.candidates[-1:]
```
