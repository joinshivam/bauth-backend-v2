const express = require("express");
const router = express.Router();

const { requireAdminPanelAuth } = require("../middleware/adminPanel.middleware");
const { requireGlobalAdmin } = require("../middleware/globalAdmin.middleware");
const admin = require("../controllers/idpAdmin.controller");
const corsAdmin = require("../controllers/corsAdmin.controller");

router.get("/admin/login", admin.login);
router.get("/admin/callback", admin.callback);

router.use("/admin", requireAdminPanelAuth, requireGlobalAdmin);

router.get("/admin", admin.dashboard);
router.get("/admin/cors", corsAdmin.list);
router.get("/admin/cors/create", corsAdmin.createPage);
router.post("/admin/cors/create", corsAdmin.add);
router.get("/admin/cors/:id/edit", corsAdmin.editPage);
router.post("/admin/cors/:id/edit", corsAdmin.update);
router.post("/admin/cors/:id/delete", corsAdmin.delete);
router.post("/admin/cors/:id/online", corsAdmin.markOnline);
router.post("/admin/cors/:id/offline", corsAdmin.markOffline);
router.post("/admin/cors/:id/allow", corsAdmin.allow);
router.post("/admin/cors/:id/block", corsAdmin.block);

router.get("/admin/services", admin.services);
router.get("/admin/services/create", admin.createPage);
router.post("/admin/services/create", admin.createService);

router.get("/admin/services/:id", admin.detailPage);
router.get("/admin/services/:id/edit", admin.editPage);
router.post("/admin/services/:id/edit", admin.updateService);

module.exports = router;
