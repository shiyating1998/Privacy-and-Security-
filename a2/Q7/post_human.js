const XHR = new XMLHttpRequest();
const FD  = new FormData();
FD.append('title', 'new post haha');
FD.append('content', 'you just created a post');
FD.append('type', 1);
FD.append('form', 'content');
XHR.open( 'POST', 'post.php' );
XHR.send( FD );