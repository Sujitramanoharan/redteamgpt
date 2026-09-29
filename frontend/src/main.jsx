import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './app-shell.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
