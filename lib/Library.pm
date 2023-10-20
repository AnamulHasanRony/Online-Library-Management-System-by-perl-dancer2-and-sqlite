package Library;
use Dancer2;

use Dancer2;
use Dancer2::Plugin::Database;
use Dancer2::Plugin::Auth::Tiny;
use Crypt::SaltedHash;
use DateTime;  

use Dancer2::Session::Simple;

use DBI;

set public => path(dirname(__FILE__), 'public');

# Establish a database connection
my $dbh = DBI->connect("dbi:SQLite:dbname=mydatabase.db", "", "");
if ($dbh && $dbh->ping) {
    # Handle is connected
    debug("Database handle is connected.");
} else {
    # Handle is not connected
    debug("Database handle is not connected.");
}

my $create_table = <<'SQL';
CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    author TEXT;
    description TEXT,
    image TEXT
);
SQL

$dbh->do($create_table);


# Enable session handling
set session => 'YAML';

our $VERSION = '0.1';

set plugins => {
    Database => {
        driver   => 'SQLite',
        database => 'C:\Users\Anamul Hasan\Atachment\Sqlite\myapp.db', # Path to your SQLite database
    },
};
my $dbh2 = database();
# Helper function to hash passwords
sub hash_password {
    my ($password) = @_;
    my $salted_hash = Crypt::SaltedHash->new(algorithm => 'SHA-1');
    $salted_hash->add($password);
    return $salted_hash->generate;
}

get '/' => sub {
    template 'index' => { 'title' => 'Library' };
};

post '/contact' => sub {

    

 my $name = param('name'); 
    my $email = param('email');
    my $subject = param('subject');
    my $message = param('message');

    # Insert the book information into the database
    my $insert = $dbh->prepare("INSERT INTO contact (name, email, subject, message) VALUES (?, ?, ?, ?)");
    $insert->execute($name, $email, $subject, $message);


    redirect '/';

    
   
};
get '/register' => sub {
    template 'register' => { 'title' => 'Library' };
};


post '/register' => sub {
    if (not session('user')) {
    my $username = param('username');
    my $mobileno = param('mobileno');
    my $email= param('email');
    my $password=param('password');
    if($username eq 'admin'){
       redirect '/register?error=1'; 
    }

    my $hashed_password = hash_password($password);
my $dbh = DBI->connect("dbi:SQLite:dbname=mydatabase.db", "", "", { RaiseError => 1 });
    my $insert = $dbh->prepare("INSERT INTO users (username, password, email, mobileno) VALUES (?, ?, ?, ?)");

# Bind and execute the statement
$insert->execute($username, $hashed_password, $email, $mobileno);

    # database->quick_insert('users', { username => $username,password => $hashed_password,email=>$email,mobileno=>$mobileno  });
    redirect '/login';
    }
    else{
    redirect '/';
    }
};


get '/login' => sub {
    if (not session('user')) {
    template 'login' => { 'title' => 'Library' };
    }
};

post '/login' => sub {
    my $username= param('username');
    my $password=param('password');
   

    # my $user = database->quick_select('users', { username => $username });
    my $select = $dbh->prepare("SELECT * FROM users WHERE username = ?");
    $select->execute($username);


    my $user = $select->fetchrow_hashref;
    
    if($username eq 'admin' && $password eq'admin'){
       session 'user' => $username;
        redirect '/admin';
    }
    if ($user && Crypt::SaltedHash->validate($user->{password}, $password)) {
        session 'user' => $username;
        redirect '/user';
    } else {
        redirect '/login?error=1';
    }

};
get '/logout' => sub {
     session->expires(-1);
    redirect '/';
};

get '/admin' =>sub {
    if (session('user')) {
        my $user = session('user');
        template 'Admin_dashboard' => { 'title' => 'Library' };        
    } else {
        return "Session variable 'admin' does not exist or is undefined.";
    }
};
get '/user' => sub {
    if(session('user')){
    template 'user_dashboard' => { 'title' => 'Library' };

    }
    else{
redirect '/login';
    }
};


get '/image/:id' => sub {
    my $id = params->{id};
    my $image = database->quick_lookup('books', { id => $id }, 'image');
    
    return send_file($image) if $image;
    status 404;
};

get '/admin/EditBooks' => sub {
    my $select = $dbh->prepare("SELECT * FROM books");
    $select->execute();
    unless ($select->execute()) {
    die "SQL Error: " . $dbh->errstr;
}

    my @books;
    while (my $book = $select->fetchrow_hashref()) {
        push @books, $book;
    }
   if(session('user')=='admin'){
     template 'Admin_BookView' => { books => \@books };
   }
#    elsif(seession('user')){
# template 'user/BookView' => { books => \@books };
#    }
#    else{
# template 'normal/BookView' => { books => \@books };
#    }
    
};

post '/admin/add' => sub {

    if(session('user') eq 'admin'){

 my $image = param('image'); # Handle image upload
    my $title = param('title');
    my $author = param('author');
    my $description = param('description');

    # Insert the book information into the database
    my $insert = $dbh->prepare("INSERT INTO books (image, title, author, description) VALUES (?, ?, ?, ?)");
    $insert->execute($image, $title, $author, $description);


    redirect '/admin/EditBooks';

    }
   
};

get '/admin/remove' => sub {
    my $book_id = param('id');
    # Remove the book from the database
    my $delete = $dbh->prepare("DELETE FROM books WHERE id = ?");
    $delete->execute($book_id);

    redirect '/admin/EditBooks';
};


get '/admin/Manage_Users' => sub {

my @books;
    my $query_sql = "SELECT * FROM users";
    
    # my $sth = $dbh2->prepare($query_sql);
    my $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    my @results;
    while (my $row = $sth->fetchrow_hashref) {
        push @results, $row;
    }
    if(session('user') eq 'admin'){
template 'Manage_Users' => { results => \@results };
   }

};


get '/admin/user_remove' => sub {
    my $user_id = param('id');
    # Remove the book from the database
    # my $delete = $dbh2->prepare("DELETE FROM users WHERE id = ?");
        my $delete = $dbh->prepare("DELETE FROM users WHERE id = ?");

    $delete->execute($user_id);

    redirect '/admin/Manage_Users';
};


get '/user/User_BorrowBooks' => sub {

my @books;
    my $query_sql = "SELECT * FROM books";
    
    my $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    
    while (my $row = $sth->fetchrow_hashref) {
        push @books, $row;
    }
    if(session('user')){
template 'User_BorrowBooks' => { books => \@books };
   }

};



get '/user/borrow' => sub {
    if(not session('user')){
get '/login';
    }
    my $book_id = param('id');
    
    # Step 1: Retrieve the data from the 'books' table
    my $select = $dbh->prepare("SELECT * FROM books WHERE id = ?");
    $select->execute($book_id);
    my $book_data = $select->fetchrow_hashref;

    if ($book_data) {
        my $delete = $dbh->prepare("DELETE FROM books WHERE id = ?");
        $delete->execute($book_id);
# my $dbh = DBI->connect("dbi:SQLite:dbname=mydatabase.db", "", "", { RaiseError => 1 });

        my $insert = $dbh->prepare("INSERT INTO borrow (id, title, author, description, borrower, borrow_time) VALUES (?, ?, ?, ?, ?, ?)");
        my $u=session('user');
        my $t=DateTime->now->strftime('%Y-%m-%d %H:%M:%S');
print "SQL: " . $insert->{Statement} . "\n";
        $insert->execute(
            $book_data->{id},
            $book_data->{title},
            $book_data->{author},
            $book_data->{description},
            $u,
            $t
            
        );

        redirect '/user/User_BorrowBooks';

        
    } 
};






get '/user/User_ReturnBooks' => sub {

my @books;
    my $query_sql = "SELECT * FROM borrow";
    
    my $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    
    while (my $row = $sth->fetchrow_hashref) {
        push @books, $row;
    }
    if(session('user')){
template 'User_ReturnBooks' => { books => \@books };
   }

};



get '/user/return' => sub {
    if(not session('user')){
get '/login';
    }
    my $book_id = param('id');
    
    # Step 1: Retrieve the data from the 'books' table
    my $select = $dbh->prepare("SELECT * FROM borrow WHERE id = ?");
    $select->execute($book_id);
    my $book_data = $select->fetchrow_hashref;

    if ($book_data) {
        my $delete = $dbh->prepare("DELETE FROM borrow WHERE id = ?");
        $delete->execute($book_id);
# my $dbh = DBI->connect("dbi:SQLite:dbname=mydatabase.db", "", "", { RaiseError => 1 });

        my $insert = $dbh->prepare("INSERT INTO books (id, title, author, description, image) VALUES (?, ?, ?, ?, ?)");
        my $u=session('user');
        my $t=DateTime->now->strftime('%Y-%m-%d %H:%M:%S');
print "SQL: " . $insert->{Statement} . "\n";
        $insert->execute(
            $book_data->{id},
            $book_data->{title},
            $book_data->{author},
            $book_data->{description},
            'this is a path'
            
        );

        redirect '/user/User_ReturnBooks';

        
    } 
};



get '/admin/Issued_Books' => sub {

my @books;
    my $query_sql = "SELECT * FROM borrow";
    
    my $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    
    while (my $row = $sth->fetchrow_hashref) {
        push @books, $row;
    }
    if(session('user')){
template 'Issued_Books' => { books => \@books };
   }

};



get '/admin/return' => sub {
    if( session('user') eq 'admin'){

    }
    else{
        get '/login';
    }
    my $book_id = param('id');
    
    # Step 1: Retrieve the data from the 'books' table
    my $select = $dbh->prepare("SELECT * FROM borrow WHERE id = ?");
    $select->execute($book_id);
    my $book_data = $select->fetchrow_hashref;

    if ($book_data) {
        my $delete = $dbh->prepare("DELETE FROM borrow WHERE id = ?");
        $delete->execute($book_id);
# my $dbh = DBI->connect("dbi:SQLite:dbname=mydatabase.db", "", "", { RaiseError => 1 });

        my $insert = $dbh->prepare("INSERT INTO books (id, title, author, description, image) VALUES (?, ?, ?, ?, ?)");
        my $u=session('user');
        my $t=DateTime->now->strftime('%Y-%m-%d %H:%M:%S');
print "SQL: " . $insert->{Statement} . "\n";
        $insert->execute(
            $book_data->{id},
            $book_data->{title},
            $book_data->{author},
            $book_data->{description},
            'this is a path'
            
        );

        redirect '/admin/Issued_Books';

        
    } 
};

get '/book' => sub {

my @books;
    my $query_sql = "SELECT * FROM borrow";
    
    my $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    
    while (my $row = $sth->fetchrow_hashref) {
        push @books, $row;
    }

    my @results;
     $query_sql = "SELECT * FROM books";
    
    $sth = $dbh->prepare($query_sql);
$sth->execute() or die "SQL Error: $DBI::errstr";

    
    while (my $row = $sth->fetchrow_hashref) {
        push @results, $row;
    }
    
template 'Booklist' => { books => \@books,
                        results => \@results
                         };
   

};


true;
