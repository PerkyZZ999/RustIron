/** The App detail tabs, shared by the route's search check and the page. */
export const APP_TABS = ["overview", "deployments", "config"] as const;
export type AppTab = (typeof APP_TABS)[number];
