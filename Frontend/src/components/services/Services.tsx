'use client'


import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { PiggyBank, TrendingUp, BookOpen, Target, Shield, Users, DollarSign, Gift } from 'lucide-react'

const GridBackground = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute inset-0 bg-gradient-to-tr from-blue-500/10 via-purple-500/10 to-teal-500/10" />
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
    </div>
  )
}

const services = [
  {
    icon: PiggyBank,
    title: "Smart Savings",
    description: "Set and track savings goals with interactive tools and visual progress indicators.",
    color: "text-green-400"
  },
  {
    icon: TrendingUp,
    title: "Budget Mastery",
    description: "Learn to create and manage budgets with our intuitive, teen-friendly budgeting system.",
    color: "text-blue-400"
  },
  {
    icon: BookOpen,
    title: "Financial Education",
    description: "Access a library of age-appropriate financial lessons, quizzes, and interactive content.",
    color: "text-purple-400"
  },
  {
    icon: Target,
    title: "Goal Setting",
    description: "Define short-term and long-term financial goals with guided assistance and milestone tracking.",
    color: "text-red-400"
  },
  {
    icon: Shield,
    title: "Secure Transactions",
    description: "Experience safe, parent-approved financial activities in a controlled environment.",
    color: "text-yellow-400"
  },
  {
    icon: Users,
    title: "Community Challenges",
    description: "Participate in savings challenges with peers to boost your financial skills and motivation.",
    color: "text-pink-400"
  },
  {
    icon: DollarSign,
    title: "Virtual Allowance",
    description: "Manage your allowance digitally, with options for automatic savings allocations.",
    color: "text-indigo-400"
  },
  {
    icon: Gift,
    title: "Rewards Program",
    description: "Earn points and badges as you improve your financial skills and reach your goals.",
    color: "text-orange-400"
  }
]

export default function ServicesPage() {
  return (
    <div className="relative min-h-screen bg-gradient-to-r from-gray-900 via-blue-900 to-gray-900 text-white py-12 px-4 sm:px-6 lg:px-8 overflow-hidden">
      <GridBackground />
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        className="max-w-7xl mx-auto"
      >
        <h1 className="text-4xl md:text-5xl font-bold text-center mb-4">Our Services</h1>
        <p className="text-xl text-gray-300 text-center mb-12">
          Empowering teens with the tools and knowledge for financial success.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {services.map((service, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <Card className="bg-gray-800/50 backdrop-blur-lg border-gray-500/50 h-full  transition-all duration-300 transform hover:rotate-6 hover:shadow-neon">
                <CardHeader>
                  <service.icon className={`h-12 w-12 ${service.color} mb-4`} />
                  <CardTitle className="text-xl font-semibold text-white">{service.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-gray-300">{service.description}</CardDescription>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          className="mt-16 text-center"
        >
          <h2 className="text-3xl font-bold mb-6">Ready to start your financial journey?</h2>
          <Button className="bg-blue-500 text-white hover:bg-blue-600 text-lg px-8 py-3 rounded-full transition-all duration-300 ease-in-out transform hover:scale-105">
            Get Started Now
          </Button>
        </motion.div>
      </motion.div>
    </div>
  )
}

<style >{`
  .shadow-neon {
    box-shadow: 0 0 5px #00ffff, 0 0 10px #00ffff;
  }
`}</style>