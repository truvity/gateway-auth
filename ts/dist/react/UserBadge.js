import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Button, Chip, Typography } from "@mui/material";
/** UserBadge is the fleet console header block: the caller's name over their
 * email, the app role as a chip, and a Sign out button that clears the
 * gateway session. Extracted from the github-roster console so every app
 * behind gateway-auth ships the same header. */
export function UserBadge({ me, signOutHref = "/oauth2/sign_out", emphasizeRoles = ["operator"] }) {
    if (!me)
        return null;
    const name = me.name || me.email || "signed in";
    return (_jsxs(Box, { sx: { display: "flex", alignItems: "center", gap: 1.5 }, children: [_jsxs(Box, { sx: { textAlign: "right", lineHeight: 1.15 }, children: [_jsx(Typography, { variant: "body2", children: name }), me.name && me.email && _jsx(Typography, { variant: "caption", color: "text.secondary", children: me.email })] }), me.role && (_jsx(Chip, { label: me.role, size: "small", variant: "outlined", color: emphasizeRoles.includes(me.role) ? "success" : "default" })), _jsx(Button, { href: signOutHref, size: "small", variant: "outlined", title: "Clear the session and sign out", children: "Sign out" })] }));
}
//# sourceMappingURL=UserBadge.js.map