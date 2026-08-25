/** Me is the signed-in caller as the app's own identity endpoint reports it
 * (a GetMe RPC behind the gateway, typically). The component is deliberately
 * presentational: apps fetch with their own client and hand the result over,
 * so this package stays free of any RPC dependency. */
export interface Me {
    name?: string;
    email?: string;
    /** The app-level role label to show (e.g. "operator", "viewer"). */
    role?: string;
}
export interface UserBadgeProps {
    /** The caller, or null while loading / when unknown (renders nothing). */
    me: Me | null;
    /** Where "Sign out" navigates — build it with signOutUrl() from the core
     * package so the proxy prefix is honored. Defaults to oauth2-proxy's
     * standard endpoint. */
    signOutHref?: string;
    /** Role values shown with the success color; every other role is neutral. */
    emphasizeRoles?: string[];
}
/** UserBadge is the fleet console header block: the caller's name over their
 * email, the app role as a chip, and a Sign out button that clears the
 * gateway session. Extracted from the github-roster console so every app
 * behind gateway-auth ships the same header. */
export declare function UserBadge({ me, signOutHref, emphasizeRoles }: UserBadgeProps): import("react").JSX.Element | null;
//# sourceMappingURL=UserBadge.d.ts.map