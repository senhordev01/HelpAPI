const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwiZW1haWwiOiJyMUBnbWFpbC5jb20iLCJpYXQiOjE3NzgzODcwMzIsImV4cCI6MTc3ODM5NDIzMn0.4pNsBfu8OLc1Y1C28bM55XCJRV2DRPcdgkDrbENMpfg";
fetch("http://localhost:5000/autonomos/4", {
    headers: {
        Authorization: `Bearer ${token}`
    }
})
.then(res => res.json())
.then(data => {
    console.log(data);
});
