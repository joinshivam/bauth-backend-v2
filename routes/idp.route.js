const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth.middleware");
const registry = require("../controllers/idpRegistry.controller");
const flow = require("../controllers/idpFlow.controller");
const { requireProjectAdmin } = require("../middleware/idpAdmin.middleware");

router.post("/projects", auth, registry.createProject);
router.post("/projects/:projectId/registration-tokens",auth,requireProjectAdmin,registry.createRegistrationToken);
router.post("/services/register", registry.registerService);
router.get("/services/me", registry.serviceDetails);
router.put("/services/me", registry.updateServiceDetails);

router.post("/flows/account-center", flow.initAccountCenterFlow);
router.post("/flows/init", flow.initExternalFlow);
router.get("/flows/:flowId", flow.getFlow);
router.post("/flows/:flowId/approve", auth, flow.approveFlow);

router.post("/token", flow.token);

module.exports = router;
