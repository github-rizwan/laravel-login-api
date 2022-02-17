<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request-> validate([
            'email '=>'required|String',
            'password'=>'required|String'

        ]);

        $credentials = request(['email','password']);

        if(!Auth::attempt($credentials)){
            return response()->json([
                'message'=>'Invalid email or password'
            ], 401);
        }

        $user = $request->user();

        $token = $user->createToken('Access Token');

        $user->access_token = $token->accessToken;

        return response()->json([
            "user"=>$user
        ],200);
    }

    public function signup(Request $request)
    {
        $request-> validate([
            'name'=>'required|String',
            'email'=>'required|String|unique:users',
            'password'=> 'required|String|confirmed'

        ]);

        $user = new User([
            'name'=>$request->name,
            'email'=>$request->email,
            'password'=>bcrypt($request->password) 
        ]);

        $user-> save();

        return response()->json([
            "message" => "User registered successfully"
        ],201);
        
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            "message" => "User Logged out successfully"
        ],200);
    }

    public function index()
    {
        echo "Hello world";
    }
}
