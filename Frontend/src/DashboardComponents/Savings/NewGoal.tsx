import { Input} from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { useState } from "react"


function NewGoal(){

    const [title,setTitle]= useState("")
    const [amount,setAmount]=useState("")
    const [description,setDescription]=useState("")

    return(
       <div className="flex justify-center items-center w-screen my-3.5">
        <div className="border p-9 rounded w-3/5 shadow-lg">
            <div className="mb-7">
                <h1 className="font-extrabold text-3xl ">Set your new Goal!</h1>
            </div>
            <div className="my-4">
                <label htmlFor="i1" className="font-semibold">Title</label>
                <Input id="i1" placeholder="title" value={title} onChange={(e)=>{
                    setTitle(e.target.value)
                }} className="border border-gray-300  focus:ring-0 focus:outline-none focus:border-opacity-50 focus:border-2 bg-background  placeholder:text-base placeholder:text-slate-400 px-3 py-2 rounded-md" ></Input>
            </div>
            <div className="my-4 flex flex-col">
                <label htmlFor="i2" className="font-semibold">Amount</label>
                <input type="number" id="i2" placeholder="Enter the amount"value={amount} onChange={(e)=>{
                    setAmount(e.target.value)
                }} className="border border-gray-300  focus:ring-0 focus:outline-none focus:border-opacity-50 focus:border-2 bg-background  placeholder:text-base placeholder:text-slate-400 px-3 py-2 rounded-md " ></input>
            </div>
            <div className="flex flex-col my-4">
                <label htmlFor="i3" className="font-semibold">Description</label>
                <textarea name="" id="i3" placeholder="Enter the description of your goal " className="border border-gray-300  focus:ring-0 focus:outline-none focus:border-opacity-50 focus:border-2 bg-background  placeholder:text-base placeholder:text-slate-400 px-3 py-2 rounded-md" value={description} onChange={(e)=>{
                    setDescription(e.target.value)
                }}></textarea>
            </div>
            <div className="flex flex-col my-4">
                <label htmlFor="i4" className="font-semibold">Upload the svg</label>
                <input type="file" name="" id="i4" className="mt-1 bg-background" />
            </div>
            <Button className="px-6 mt-3 bg-green-600 text-white">Submit</Button>
        </div>
       </div>
    )
}

export default NewGoal