'use client'


import { Button } from "@/components/ui/button"
import { Link } from "react-router-dom"
import { motion } from "framer-motion"
import { Wallet, TrendingUp, PieChart, Shield } from 'lucide-react'

const GridBackground = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-tr from-blue-500/10 via-purple-500/10 to-teal-500/10" />
      
      {/* Grid pattern */}
      <div 
        className="absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255,255,255,0.1) 2px, transparent 2px),
            linear-gradient(to bottom, rgba(255,255,255,0.1) 2px, transparent 2px)
          `,
          backgroundSize: '60px 60px',
          maskImage: 'radial-gradient(circle at center, black, transparent 80%)'
        }}
      />

      {/* Animated glow effects */}
      <div className="absolute -left-20 -top-20 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob" />
      <div className="absolute -right-20 -bottom-20 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000" />
      <div className="absolute left-1/2 top-1/2 w-96 h-96 bg-teal-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-4000" />
    </div>
  )
}

const FeatureCard = ({ icon: Icon, title, description }) => (
  <motion.div 
    className="bg-gray-800/50 backdrop-blur-md rounded-lg p-6 shadow-lg border border-gray-700/50"
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5 }}
    whileHover={{ 
      rotate: 6, 
      scale: 1.05,
      boxShadow: '0 0 25px rgba(59, 130, 246, 0.5)'
    }}
    style={{
      boxShadow: '0 0 15px rgba(59, 130, 246, 0.3)'
    }}
  >
    <Icon className="w-12 h-12 text-blue-400 mb-4" />
    <h3 className="text-xl font-semibold text-white mb-2">{title}</h3>
    <p className="text-gray-300">{description}</p>
  </motion.div>
)

export default function HomePage() {
  return (
    <div className="relative min-h-screen bg-gradient-to-r from-gray-900 via-blue-900 to-gray-900 text-gray-300 flex flex-col overflow-hidden">
      <GridBackground />

      {/* Main content */}
      <main className="relative  flex-grow flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-16 my-5 z-0">
        <motion.div 
          className="max-w-4xl w-full"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <div className="bg-gray-800/30 backdrop-blur-xl rounded-lg p-8 md:p-12 shadow-2xl border border-gray-700/50 text-center mb-12">
            <motion.h1 
              className="text-5xl md:text-6xl font-bold mb-6 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-purple-400 to-teal-400 animate-text-shine"
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
            >
              Welcome to Finance
            </motion.h1>
            <motion.p 
              className="mb-8 text-xl md:text-2xl text-gray-300"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4 }}
            >
              Empowering your financial journey with expert insights and innovative solutions.
            </motion.p>
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8, delay: 0.6 }}
            >
              <Link to={'/login'}>
                <Button className="bg-blue-500 text-white hover:bg-blue-600 text-lg md:text-xl px-8 py-3 transition-all duration-300 ease-in-out shadow-[0_0_15px_rgba(59,130,246,0.5)] hover:shadow-[0_0_25px_rgba(59,130,246,0.7)] hover:scale-105">
                  Get Started
                </Button>
              </Link>
            </motion.div>
          </div>

          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <FeatureCard 
              icon={Wallet}
              title="Smart Budgeting"
              description="Effortlessly manage your finances with our intuitive budgeting tools."
            />
            <FeatureCard 
              icon={TrendingUp}
              title="Investment Insights"
              description="Get expert advice and real-time market analysis to grow your wealth."
            />
            <FeatureCard 
              icon={PieChart}
              title="Financial Planning"
              description="Plan for your future with our comprehensive financial planning services."
            />
            <FeatureCard 
              icon={Shield}
              title="Secure Transactions"
              description="Rest easy knowing your financial data is protected by state-of-the-art security."
            />
          </div>
        </motion.div>
      </main>

      <style >{`
        @keyframes blob {
          0% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
          100% { transform: translate(0px, 0px) scale(1); }
        }
        @keyframes text-shine {
          0% { background-position: 0% 50%; }
          100% { background-position: 100% 50%; }
        }
        .animate-blob {
          animation: blob 7s infinite;
        }
        .animation-delay-2000 {
          animation-delay: 2s;
        }
        .animation-delay-4000 {
          animation-delay: 4s;
        }
        .animate-text-shine {
          background-size: 200% auto;
          animation: text-shine 3s linear infinite;
        }
      `}</style>
    </div>
  )
}