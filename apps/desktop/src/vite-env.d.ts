// Allow importing files as raw strings (e.g. the changelog rendered under Settings → Updates).
declare module "*?raw" {
  const content: string;
  export default content;
}
