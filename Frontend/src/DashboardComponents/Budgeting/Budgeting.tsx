import React, { useEffect } from 'react'
import { useState } from 'react'
import { Pie, PieChart, Cell, ResponsiveContainer, Legend } from 'recharts'
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { 
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { 
  DollarSign, 
  ShoppingBag, 
  Smartphone, 
  Coffee, 
  Film, 
  Gamepad,
  PlusCircle
} from 'lucide-react'

const expenseData = [
    { name: 'Shopping', value: 300, color: '#FF6384', icon: ShoppingBag },
    { name: 'Phone', value: 200, color: '#36A2EB', icon: Smartphone },
    { name: 'Food', value: 250, color: '#FFCE56', icon: Coffee },
    { name: 'Entertainment', value: 150, color: '#4BC0C0', icon: Film },
    { name: 'Gaming', value: 1000, color: '#9966FF', icon: Gamepad },
  ]



const BudgetOverview = ({ income, expenses, savings }) => (
  <Card className='animate-fadeIn shadow-lg'>
    <CardHeader>
      <CardTitle className='animate-slideDown'>Budget Overview</CardTitle>
      <CardDescription>Your monthly budget at a glance</CardDescription>
    </CardHeader>
    <CardContent>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span>Income</span>
          <span className="font-bold text-green-500">{income}</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Expenses</span>
          <span className="font-bold text-red-500">{expenses}</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Savings</span>
          <span className="font-bold text-blue-500">{savings}</span>
        </div>
        <Progress value={(expenses / income) * 100} className="h-2" />
        <p className="text-sm text-muted-foreground">
          You've spent {((expenses / income) * 100).toFixed(1)}% of your income
        </p>
      </div>
    </CardContent>
  </Card>
)

const ExpenseBreakdown = () => (
  <Card className='shadow-lg'>
    <CardHeader>
      <CardTitle className='animate-slideDown'>Expense Breakdown</CardTitle>
      <CardDescription>Where your money is going</CardDescription>
    </CardHeader>
    <CardContent className="pt-0">
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={expenseData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={80}
            label
          >
            {expenseData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </CardContent>
  </Card>
)



interface Expense {
  id: number;
  title: string;
  amount: string;
  category: string;
}

const RecentTransactions = () => {
  const [Expenses, setExpenses] = useState<Expense[]>([]); // Specify type as an array of Expense
  const [Loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchExpenses = async () => {
      try {
        const response = await fetch("http://127.0.0.1:8000/api/budgeting/expenses/");
        const data: Expense[] = await response.json(); // Cast API response to the Expense array type
        console.log(data); // Log fetched data
        setExpenses(data);
      } catch (err) {
        console.error("Error fetching expenses:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchExpenses();
  }, []);

  return (
    <Card className="animate-slideUp shadow-lg">
      <CardHeader>
        <CardTitle>Recent Transactions</CardTitle>
        <CardDescription>Your latest spending activity</CardDescription>
      </CardHeader>
      <CardContent>
        {Loading ? (
          <p>Loading...</p> // Show a loading message while data is being fetched
        ) : Expenses.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Category</TableHead>
                <TableHead>Title</TableHead>
                <TableHead className="text-right">Amount</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {Expenses.map((item) => (
                <TableRow key={item.id}>
                  <TableCell>{item.category}</TableCell>
                  <TableCell>{item.title}</TableCell>
                  <TableCell className="text-right">{item.amount}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <p>No transactions found.</p> // Handle case when no data is returned
        )}
      </CardContent>
    </Card>
  );
};




const AddExpenseForm = () => {
  
 const [expenseName, setExpenseName] = useState('')
 const [amount, setAmount] = useState('')
 const [category, setCategory] = useState('Shopping')
 
 

 const handleSubmit = async (e)=>{
  e.preventDefault()
  
  try {
    
    
    const response = await fetch("http://127.0.0.1:8000/api/budgeting/expenses/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title: expenseName,
        amount:amount ,
        category:category,
        
        
      })
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      console.log(JSON.stringify(errorData));
      
    }
   
    
  } catch (error:any) {
    
    throw Error(error);
  }
  
};
  return(
  <Card className='shadow-lg'>
    <CardHeader>
      <CardTitle>Add New Expense</CardTitle>
      <CardDescription>Keep track of your spending</CardDescription>
    </CardHeader>
    <CardContent>
      <form className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="expense-name">Expense Name</Label>
            <Input id="expense-name" placeholder="e.g., Movie Ticket" value={expenseName} onChange={(e)=>{
              setExpenseName(e.target.value)
            }}/>
          </div>
          <div className="space-y-2">
            <Label htmlFor="expense-amount">Amount</Label>
            <div className="relative">
              <DollarSign className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <Input id="expense-amount" type="number" className="pl-8" placeholder="0.00" value={amount} onChange={(e)=>{
                setAmount(e.target.value)
              }} />
            </div>
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="expense-category">Category</Label>
          <select id="expense-category" className="w-full p-2 border bg-background rounded-md" value={category} onChange={(e)=>setCategory(e.target.value)}>
            <option>Shopping</option>
            <option>Food</option>
            <option>Entertainment</option>
            <option>Other</option>
          </select>
        </div>
        <Button className="w-full" onClick={handleSubmit}>
          <PlusCircle className="mr-2 h-4 w-4" /> Add Expense
        </Button>
      </form>
    </CardContent>
  </Card>)
}

export default function BudgetingPage() {
    
    

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold tracking-tight animate-slideDown">Budgeting Dashboard</h1>
      
      <div className="grid gap-6 md:grid-cols-2">
        <BudgetOverview income={5000} expenses={3000} savings={2000} />
        <ExpenseBreakdown />
      </div>

      <RecentTransactions  />

      <AddExpenseForm />

      <Card>
        <CardHeader>
          <CardTitle>Budgeting Tips for Teens</CardTitle>
          <CardDescription>Smart ways to manage your money</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="list-disc pl-5 space-y-2">
            <li>Track every expense, no matter how small</li>
            <li>Set realistic savings goals</li>
            <li>Differentiate between needs and wants</li>
            <li>Look for ways to earn extra income</li>
            <li>Learn to comparison shop for better deals</li>
          </ul>
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