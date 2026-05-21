const router = require('express').Router();
router.get("/health", (req, res) => {
    res.json({
        msg: "hello"
    });
})
router.get("/api/components/oneheader/v1", (req, res) => {
    res.json({
        library: `@parallel-auth/one-header/version1`,
        code: `<IdentityPlatform
  config={{
    apiBase: "http://localhost:5000",
    accountCenterUrl: "http://localhost:5000/account-center",
    loginUrl: "http://localhost:5000/login"
  }}
  header={{ fixed: false }}
/>`,
 setup:`<div id="bauth-header"></div>

<script>
  window.BAuth.mount({
    target: "#bauth-header",
    config: {
      apiBase: "http://localhost:5000",
      accountCenterUrl: "http://localhost:5000/account-center"
    },
    header: { fixed: false }
  });
</script>`
    });
})