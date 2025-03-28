import  { useState,useEffect} from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader } from 'lucide-react'




function Login() {
  const [email,setEmail]=useState("")
  const [password,setPassword]=useState("")
  const [errorEmail,setErrorEmail]=useState("")
  const [errorPassword,setErrorPassword]=useState("")
  const [error,setError]=useState("")
  const [loading,setLoading]=useState(false)
  const [data, setData] = useState(null);
  const navigate = useNavigate()


  
  const handleSubmit = async (e)=>{
    e.preventDefault()
    
    try {
      setLoading(true)
      new Promise((resolve)=>{setTimeout(resolve,2000)})
      const response = await fetch("http://127.0.0.1:8000/api/auth/login/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          
          email:email,
          password:password,
          
        }),
      });
      setTimeout(()=>{
        setLoading(false)
      },2000)
      if (!response.ok) {
        const errorData = await response.json();
        setErrorEmail(JSON.stringify(errorData.email))
        setErrorPassword(JSON.stringify(errorData.error))
        if(errorEmail || errorPassword){
          setError("Invalid credentials")
        }
        throw Error(JSON.stringify(errorData));
      }
      else{
        navigate("/dashboard")
      }
    } catch (error: any) {
      setLoading(false)
      throw Error(error);
    }
  };
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
        <h2 className="text-2xl font-bold text-center mb-4 text-stone-800">Login</h2>
        <form onSubmit={handleSubmit} >
          <div className="mb-4">
            <label className="block text-gray-700 font-semibold mb-2">
              Email
            </label>
            <input
              type="text"
              name="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:outline-none text-black focus:ring-2 focus:ring-blue-400"
              placeholder="Enter your username"
              required
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
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 text-black "
              placeholder="Enter your password"
              required
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-500 text-white py-2 px-4 rounded-lg hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
          >
            {loading?(<span className='flex justify-center items-center'><Loader className='animate-spin'></Loader></span>):('Login')}
          </button>
          <div className='text-red-600 flex justify-center my-3 '>{error}</div>
        </form>
        <p className="text-center text-gray-600 mt-4">
          Not registered?{" "}
          <a href="/signup" className="text-blue-500 hover:underline">
            Signup
          </a>
        </p>
      </div>
    </div>
  )
}

export default Login

