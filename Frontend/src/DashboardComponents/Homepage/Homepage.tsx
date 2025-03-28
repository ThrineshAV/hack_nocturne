
import { Bar, BarChart, ResponsiveContainer, XAxis, YAxis } from 'recharts'
import {  DollarSign, PieChart, User } from 'lucide-react'
import { useState } from 'react'

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

function Homepage() {

    const data = [
        { name: 'Jan', total: 15 },
        { name: 'Feb', total: 20 },
        { name: 'Mar', total: 18 },
        { name: 'Apr', total: 25 },
        { name: 'May', total: 30 },
        { name: 'Jun', total: 28 },
        { name: 'Jul', total: 17 },
        { name: 'Aug', total: 22 },
        { name: 'Sep', total: 26 },
        { name: 'Oct', total: 10 },
        { name: 'Nov', total: 15 },
        { name: 'Dec', total: 23 },

      ]
      const [parentalControlsEnabled, setParentalControlsEnabled] = useState(true)
  return (
    <main className="flex-1 py-8 container px-7">
        <div className="flex flex-col space-y-8 animate-fadeIn">
          <div className="flex items-center justify-between space-y-2">
            <h2 className="text-3xl font-bold tracking-tight animate-slideDown">Dashboard</h2>
            <div className="flex items-center space-x-2">
              
            </div>
          </div>

          {/* Overview Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className='animate-slideDown shadow-lg'>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Savings</CardTitle>
                <DollarSign className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">52580.00</div>
                <p className="text-xs text-muted-foreground">+20.1% from last month</p>
              </CardContent>
            </Card>
            <Card className='animate-slideDown shadow-lg'>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Monthly Allowance</CardTitle>
                <DollarSign className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">2500.00</div>
                <p className="text-xs text-muted-foreground">Next payout in 5 days</p>
              </CardContent>
            </Card>
            <Card className='animate-slideDown shadow-lg'>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Savings Goal Progress</CardTitle>
                <PieChart className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">48%</div>
                <Progress value={48} className="mt-2" />
                <p className="text-xs text-muted-foreground mt-2">12580 / 30000 for new bike</p>
              </CardContent>
            </Card>
            <Card className='animate-slideDown shadow-lg'>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Balance</CardTitle>
                <User className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">12580</div>
                <p className="text-xs text-muted-foreground">Balance of your account</p>
              </CardContent>
            </Card>
          </div>

          {/* Savings Chart */}
          <Card className="col-span-4 shadow-lg">
            <CardHeader>
              <CardTitle>Savings Overview</CardTitle>
            </CardHeader>
            <CardContent className="pl-2">
              <ResponsiveContainer width="100%" height={350}>
                <BarChart data={data}>
                  <XAxis
                    dataKey="name"
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
                    tickFormatter={(value) => `$${value}`}
                  />
                  <Bar dataKey="total" fill="#adfa1d" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Parental Controls */}
          <Card className='animate-slideDown shadow-lg'>
            <CardHeader>
              <CardTitle>Parental Controls</CardTitle>
              <CardDescription>Manage your child's account settings and permissions.</CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="spending" className="w-full">
                <TabsList>
                  <TabsTrigger value="spending">Spending Limits</TabsTrigger>
                  <TabsTrigger value="notifications">Notifications</TabsTrigger>
                  <TabsTrigger value="access">Account Access</TabsTrigger>
                </TabsList>
                <TabsContent value="spending">
                  <div className="flex items-center justify-between py-2">
                    <div className="space-y-0.5">
                      <h3 className="text-base font-medium">Weekly Spending Limit</h3>
                      <p className="text-sm text-muted-foreground">Set a maximum weekly spending amount</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xl font-bold">500</span>
                      <Button variant="outline" size="sm">Edit</Button>
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="notifications">
                  <div className="flex items-center justify-between py-2">
                    <div className="space-y-0.5">
                      <h3 className="text-base font-medium">Transaction Alerts</h3>
                      <p className="text-sm text-muted-foreground">Receive notifications for all transactions</p>
                    </div>
                    <Switch checked={parentalControlsEnabled} onCheckedChange={setParentalControlsEnabled} />
                  </div>
                </TabsContent>
                <TabsContent value="access">
                  <div className="flex items-center justify-between py-2">
                    <div className="space-y-0.5">
                      <h3 className="text-base font-medium">Restricted Categories</h3>
                      <p className="text-sm text-muted-foreground">Block spending in certain categories</p>
                    </div>
                    <Button variant="outline" size="sm">Manage</Button>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
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
          animation: fadeIn 1s ease-out;
        }
        .animate-slideDown {
          animation: slideDown 0.8s ease-out;
        }
        .animate-slideUp {
          animation: slideUp 0.8s ease-out;
        }
      `}</style>
      </main>
  )
}

export default Homepage