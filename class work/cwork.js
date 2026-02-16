const http=require("http")
const fs=require("fs")
const url=require("url");

// const server=http.createServer((req,res)=>{
//     let response;
//     switch(req.url){
//             case '/':
//                 response="home page";
//                 break;
//             case '/about':
//                 response="about page";
//                 break;
//             case '/contact':
//                 response="contact page";
//                 break;
//             default:
//                 response="404 page not found";
//                 break; 
//         }
//     const log=`${Date.now()}|: ${req.url} |${response}\n`;
//      res.writeHead(200,
//             {
//                 "Content-Type": "text/html",

//             });
//     res.end(response);
//     fs.appendFile("log.txt",log,(err)=>{
//         if(err){
//             console.log("error try again");
//         }
//         res.end(response);
//     })
// })
// server.listen(8000,()=>{
//     console.log("server stared")
// })

const server=http.createServer((req,res)=>{
    const myUrl=url.parse(req.url,true);
    switch(req.url){
            case '/':
                response="Welcome to my Node.js HTTP server!";
                break;
            case '/about':
                response="<h1>About Page</h1><p>This is a simple Node.js server using the http module.</p>";
                break;
            case '/user':
                response=`<h1>User Page</h1><p>Username: ${myUrl.query.username}</p><p>Email: ${myUrl.query.email}</p>`;
                break;
            default:
                response="404 page not found";
                break; 
        }
         res.writeHead(200,
            {
                "Content-Type": "text/html",

            });
        res.end(JSON.stringify(response));
});
server.listen(3000,()=>{
    console.log("server is started");
});