import React, { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import PageTransition from './components/PageTransition'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import ReportViewer from './pages/ReportViewer'
import Settings from './pages/Settings'
import RuleBuilder from './pages/RuleBuilder'
import { AnimatePresence } from 'framer-motion'
import ChatBot from './components/ChatBot'
import './index.css'

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(prev => !prev)} />
        <main className={`main-content ${sidebarOpen ? '' : 'main-content-expanded'}`}>
          <AnimatePresence mode="wait">
            <Routes>
              <Route path="/" element={<PageTransition><Dashboard /></PageTransition>} />
              <Route path="/scan/new" element={<PageTransition><NewScan /></PageTransition>} />
              <Route path="/scan/:id" element={<PageTransition><ScanProgress /></PageTransition>} />
              <Route path="/scan/:id/report" element={<PageTransition><ReportViewer /></PageTransition>} />
              <Route path="/rules" element={<PageTransition><RuleBuilder /></PageTransition>} />
              <Route path="/settings" element={<PageTransition><Settings /></PageTransition>} />
            </Routes>
          </AnimatePresence>
        </main>
        <ChatBot />
      </div>
    </BrowserRouter>
  )
}
