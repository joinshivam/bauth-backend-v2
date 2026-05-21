const CorsOrigin = require("../models/corsOrigin");

function redirectToCors() {
    return "/admin/cors";
}

async function renderList(req, res, error = null) {
    const origins = await CorsOrigin.listAll();

    res.render("admin/cors", {
        user: req.user,
        origins,
        error,
    });
}

module.exports = {
    list: async (req, res) => {
        await renderList(req, res);
    },

    createPage: async (req, res) => {
        res.render("admin/cors-create", {
            user: req.user,
            error: null,
        });
    },

    add: async (req, res) => {
        try {
            await CorsOrigin.create({
                label: req.body.label,
                origin: req.body.origin,
                description: req.body.description,
                createdByUserId: req.user?.id,
            });

            res.redirect(redirectToCors());
        } catch (err) {
            res.status(400).render("admin/cors-create", {
                user: req.user,
                error: err.message || "Unable to add CORS origin",
            });
        }
    },

    editPage: async (req, res) => {
        const origin = await CorsOrigin.getById(req.params.id);

        if (!origin) {
            return res.redirect(redirectToCors());
        }

        res.render("admin/cors-edit", {
            user: req.user,
            origin,
            error: null,
        });
    },

    update: async (req, res) => {
        try {
            await CorsOrigin.update(req.params.id, {
                label: req.body.label,
                origin: req.body.origin,
                description: req.body.description,
            });

            res.redirect(redirectToCors());
        } catch (err) {
            const origin = await CorsOrigin.getById(req.params.id);

            res.status(400).render("admin/cors-edit", {
                user: req.user,
                origin: origin || {
                    id: req.params.id,
                    label: req.body.label,
                    origin: req.body.origin,
                    description: req.body.description,
                },
                error: err.message || "Unable to update CORS origin",
            });
        }
    },

    delete: async (req, res) => {
        await CorsOrigin.remove(req.params.id);
        res.redirect(redirectToCors());
    },

    markOnline: async (req, res) => {
        await CorsOrigin.markOnline(req.params.id);
        res.redirect(redirectToCors());
    },

    markOffline: async (req, res) => {
        await CorsOrigin.markOffline(req.params.id);
        res.redirect(redirectToCors());
    },

    allow: async (req, res) => {
        await CorsOrigin.allow(req.params.id);
        res.redirect(redirectToCors());
    },

    block: async (req, res) => {
        await CorsOrigin.block(req.params.id);
        res.redirect(redirectToCors());
    },
};
