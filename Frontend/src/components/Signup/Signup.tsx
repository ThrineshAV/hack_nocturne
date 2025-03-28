import  { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader } from 'lucide-react'




function Signup() {
  const [email,setEmail]=useState("")
  const [password,setPassword]=useState("")
  const [username,setUsername]=useState("")
  const [password2,setPassword2]=useState("")
  const [error,setError]=useState("")
  const [errorPassword,setErrorPassword]=useState("")
  const [loading,setLoading]=useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e)=>{
    e.preventDefault()
    
    try {
      setLoading(true)
      new Promise((resolve)=>setTimeout(resolve, 2000))
      const response = await fetch("http://127.0.0.1:8000/api/auth/register/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email:email,
          username:username,
          password:password,
          password2:password2
        })
      });
      setTimeout(()=>{
        setLoading(false)
      },2000)
      if (!response.ok) {
        const errorData = await response.json();
        console.log(errorData)
        setErrorPassword(JSON.stringify(errorData.password))
        if(errorPassword){
          setError("password is too small")
        }else{
          setError("user Already exists")
        }
        
        console.log(errorData);
        
      }
      else{
        navigate("/login")
      }
    } catch (error:any) {
      setLoading(false)
      throw Error(error);
    }
    finally{
      setLoading(false)
    }
  };
  
  
  return (
    <>
     <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
        <h2 className="text-2xl font-bold text-center mb-4 text-black">Signup</h2>
        <form onSubmit={handleSubmit} >
          <div className="mb-4">
            <label className="block text-gray-700 font-semibold mb-2">
              Username
            </label>
            <input
              type="text"
              name="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2 text-black border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Enter your username"
             
            />
          </div>
          <div className="mb-4">
            <label className="block text-gray-700 font-semibold mb-2">
              Email
            </label>
            <input
              type="email"
              name="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Enter your email"
              
            />
          </div>
          <div className="mb-6">
            <label className="block text-gray-700 font-semibold mb-2">
              Password
            </label>
            <input
              type="password"
              name="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 text-black border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Enter your password"
            
            />
          </div>
          <div className="mb-6">
            <label className="block text-gray-700 font-semibold mb-2">
              Renter Password
            </label>
            <input
              type="password"
              name="password"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              className="w-full px-4 py-2 text-black border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Enter your password"
            
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-500 text-white py-2 px-4 rounded-lg hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
          >
             {loading ? (<span className="flex items-center justify-center"><Loader className='animate-spin' />Please wait</span> ) : ('Register')}
          </button>
          <div className='text-red-700 flex justify-center items-center my-4'>{error}</div>
        </form>
        <p className="text-center text-gray-600 mt-4">
          Already registered?{" "}
          <a href="/login" className="text-blue-500 hover:underline">
            Login
          </a>
        </p>
      </div>
    </div>
      
    </>
  )
}

export default Signup

