import { mount } from 'svelte';
import './tokens.css';
import './app.css';
import './lib/theme.svelte'; // applies the saved theme before the first paint of the app
import App from './App.svelte';

const target = document.getElementById('app');
if (target) mount(App, { target });
