
import { Input } from "@/components/ui/input"
import { DollarSign, PiggyBank,  BarChart, Settings,  Search } from 'lucide-react'

import { Link } from "react-router-dom"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"


  function STF(){
    
  
    return(
       <SidebarProvider>
      <Sidebar>
        <SidebarHeader>
          <Link to={'/dashboard'} className="flex items-center space-x-2 px-4 py-2">
            <DollarSign className="h-8 w-8 text-blue-500" />
            <span className="text-xl font-bold">TeenFinance</span>
          </Link>
        </SidebarHeader>
        <SidebarContent>
          <SidebarMenu>
            
              <SidebarMenuItem >
                <SidebarMenuButton >
                  <Link to={'/dashboard'} className="flex items-center space-x-2 px-4 py-2">
                    <DollarSign className="h-5 w-5" />
                    <span>Dashboard</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem >
                <SidebarMenuButton >
                  <Link to={'/dashboard/savings'} className="flex items-center space-x-2 px-4 py-2">
                    <PiggyBank className="h-5 w-5" />
                    <span>Savings</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem >
                <SidebarMenuButton >
                  <Link to={'/dashboard/budgeting'} className="flex items-center space-x-2 px-4 py-2">
                    <BarChart className="h-5 w-5" />
                    <span>Budgeting</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem >
                <SidebarMenuButton >
                  <Link to={'/dashboard/settings'} className="flex items-center space-x-2 px-4 py-2">
                    <Settings className="h-5 w-5" />
                    <span>Settings</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            
          </SidebarMenu>
        </SidebarContent>
        <SidebarFooter>
          <form className="px-4 py-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
              <Input
                type="search"
                placeholder="Search..."
                className="pl-8"
              />
            </div>
          </form>
        </SidebarFooter>
      </Sidebar>
      <div className="flex min-h-screen flex-col">
        <header className="sticky top-4 z-10 flex  items-center gap-4  bg-transparent px-6">
          <SidebarTrigger className="" />
          <div className="flex-1" />
        </header>
        
      </div>
      </SidebarProvider> 
      
    
    )
  }

  export default STF