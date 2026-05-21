const express = require("express");
const router = express.Router();

const userController = require("../controllers/user.controller");
const authMiddleware = require("../middleware/auth.middleware");
const { uploadPhoto } = require("../middleware/upload.middleware");

router.get("/auth", authMiddleware, userController.getMe);
router.get("/auth/:username", authMiddleware, userController.getByUsername);
router.post("/user/switch", authMiddleware, userController.switchAccount);
router.post("/user/remove", authMiddleware, userController.removeAccount);
router.post("/user/logout", authMiddleware, userController.logout);
router.post("/users/logout", authMiddleware, userController.logoutAll);
router.put("/user/update/name", authMiddleware, userController.updateName);
router.put("/user/update/dob", authMiddleware, userController.updateDOB);
router.put("/user/update/gender", authMiddleware, userController.updateGender);
router.put("/user/update/username", authMiddleware, userController.updateUsername);
router.put("/user/update/phone", authMiddleware, userController.updatePhone);
router.put("/user/update/password", authMiddleware, userController.updatePassword);
router.put("/user/update/photo", authMiddleware, uploadPhoto.single("photo"), userController.updatePhoto);
router.delete("/user/delete/:id", authMiddleware, userController.delete);
module.exports = router;
