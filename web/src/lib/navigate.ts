/**
 * Sends the browser to an address that is not a view of this app, such as the sign-in page of a provider. It is
 * a function of its own so that a test can see where the app would go without leaving the test page.
 */
export function goTo(address: string): void {
  window.location.assign(address);
}
