/** Starlight resolves these component imports through Vite virtual modules. */
declare module 'virtual:starlight/components/*' {
	const component: import('astro/runtime/server/index.js').AstroComponentFactory;
	export default component;
}

declare module 'virtual:starlight/user-config' {
	const config: import('@astrojs/starlight').StarlightConfig;
	export default config;
}
