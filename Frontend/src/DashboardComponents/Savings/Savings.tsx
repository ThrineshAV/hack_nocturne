import { Bar, BarChart, ResponsiveContainer, XAxis, YAxis } from 'recharts'
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Button } from "@/components/ui/button"
import { Banknote, PiggyBank, Target, TrendingUp } from 'lucide-react'
import { Link } from 'react-router-dom'

const savingsData = [
  { month: 'Jan', amount: 50 },
  { month: 'Feb', amount: 75 },
  { month: 'Mar', amount: 90 },
  { month: 'Apr', amount: 100 },
  { month: 'May', amount: 150 },
  { month: 'Jun', amount: 180 },
  { month: 'July',amount: 100 },
  { month: 'Aug', amount: 80 },
  { month: 'Sep', amount: 120 },
  { month: 'Oct', amount: 190 },
  { month: 'Nov', amount: 90 },
  { month: 'Dec', amount: 150 },
]

const SavingsGoal = ({ title, current, target, icon: Icon }) => (
  <Card className='animate-fadeIn animate-slideDown shadow-lg'>
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium">
        {title}
      </CardTitle>
      <Icon className="h-4 w-4 text-muted-foreground" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold">{current}</div>
      <Progress 
        value={(current / target) * 100} 
        className="mt-2"
      />
      <p className="text-xs text-muted-foreground mt-2">
        {current} of {target} goal
      </p>
    </CardContent>
  </Card>
)


function Savings() {
  return (
    <div className="p-6 space-y-6">
      <h2 className="text-3xl font-bold tracking-tight animate-fadeIn animate-slideUp">Your Savings</h2>
      
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <SavingsGoal 
          title="Emergency Fund" 
          current={2500} 
          target={5000} 
          icon={Banknote}
        />
        <SavingsGoal 
          title="New Phone" 
          current={12580} 
          target={30000} 
          icon={PiggyBank}
        />
        <SavingsGoal 
          title="Summer Trip" 
          current={3000} 
          target={10000} 
          icon={Target}
        />
        <Card className='animate-fadeIn animate-slideDown shadow-lg'>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Savings
            </CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12580</div>
            <p className="text-xs text-muted-foreground">
              +15% from last month
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className='shadow-lg'>
        <CardHeader>
          <CardTitle>Savings History</CardTitle>
          <CardDescription>
            Your savings growth over the past 6 months
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-4">
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={savingsData}>
              <XAxis 
                dataKey="month" 
                stroke="#888888" 
                fontSize={12} 
                tickLine={false} 
                axisLine={false}
              />
              <YAxis
                stroke="#888888"
                fontSize={12}
                tickLine={false}
                axisLine={false}
                tickFormatter={(value) => `${value}`}
              />
              <Bar 
                dataKey="amount" 
                fill="#3b82f6" 
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card className='shadow-lg'>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Take control of your savings
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col sm:flex-row gap-4 text">
          <Link to={'/dashboard/newgoal'} className="flex-1 "><Button className='w-full' >Set New Goal</Button></Link>
          
        </CardContent>
      </Card>
      <style >{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes slideDown {
          from { transform: translateY(-20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        @keyframes slideUp {
          from { transform: translateY(20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .animate-fadeIn {
          animation: fadeIn 1.5s ease-out;
        }
        .animate-slideDown {
          animation: slideDown 0.8s ease-out;
        }
        .animate-slideUp {
          animation: slideUp 0.8s ease-out;
        }
      `}</style>
    </div>
  )
}

export default Savings