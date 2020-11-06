<?php


if(isset($_POST['signup-submit'])) { 	

	 require 'dbh.inc.php';

	 //Store all the user data in variables 
	 $firstName = $_POST['firstName'];
	 $lastName = $_POST['lastName'];
	 $gender = $_POST['gender'];
	 $email = $_POST['email'];
	 $pswd = $_POST['password'];
	 $phno = $_POST['phnumber'];

	 //check if any empty fields
	 if(empty($firstName) || empty($lastName) || empty($email) || empty($firstName) || empty($pswd) || empty($phno)){

	 	header("Location: ../signup.php?error=emptyfields&firstName=".$firstName."&lastName=".$lastName."&email=".$email."&phno=".$phno);
	 	exit();
	 }
	 //email verification
	 elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	 	header("Location: ../signup.php?error=invalidEmail&firstName=".$firstName."&lastName=".$lastName."&phno=".$phno);
	 	exit();
	 }

	 //setup connection for sql
	 else{

	 	$sql = "Select email from users_ where email=?";
	 	$stmt = mysqli_stmt_init($conn);
	 	if (!mysqli_stmt_prepare($stmt, $sql)) {
	 		header("Location: ../signup.php?error=sqlError");
	 		exit();
	 	}

	 	//check duplicate accounts
	 	else {

	 		mysqli_stmt_bind_param($stmt, "s", $email);
	 		mysqli_stmt_execute($stmt);
	 		mysqli_stmt_store_result($stmt);
	 		$resultCheck = mysqli_stmt_num_rows($stmt);
	 		if($resultCheck > 0)
	 		{
	 			header("Location: ../signup.php?error=emailalreadyexists");
	 			exit();
	 		}

	 		//add user details to database
	 		else {

	 			$sql = "INSERT into users_ (firstname, lastname, gender, email, pswd, phno) VALUES (?, ?, ?, ?, ?, ?)";
	 			$stmt = mysqli_stmt_init($conn);
	 			if(!mysqli_stmt_prepare($stmt, $sql)){ 
	 				header("Location: ../signup.php?error=sqlError");
	 				exit();
	 			}
	 			else {
	 				$hashpwd = password_hash($pswd, PASSWORD_DEFAULT);
	 				mysqli_stmt_bind_param($stmt, "ssssss", $firstName, $lastName, $gender, $email, $hashpwd, $phno);
	 				mysqli_stmt_execute($stmt);
	 				header("Location: ../login.php?signup=success");
	 				exit();
	 			}

	 		}
	 	}
	 }

	 mysqli_stmt_close($stmt);
	 mysqli_stmt_close($conn);

}

else {
	header("Location: ../signup.php");
	exit();
}