import {Outlet} from 'react-router-dom'
import Navbar from './DashboardComponents/Navbar/Navbar'
import Footer from './DashboardComponents/Footer/Footer'


function DBLayout(){
    return(
        <>
        
        <Navbar/>
        <Outlet/>
        <Footer/>
        </>
    )
}

export default DBLayout
