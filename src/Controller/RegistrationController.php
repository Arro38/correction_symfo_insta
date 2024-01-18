<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class RegistrationController extends AbstractController
{
    #[Route('/api/register', name: 'app_registration', methods: ['POST'])]
    public function index(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $em): JsonResponse
    {
        $user = new User();
        try {
            $email = $request->request->get('email');
            $password = $request->request->get('password');
            $username = $request->request->get('username');
            // TODO ADD ProfilPicture

            if ($email === null || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new \Exception('Invalid email');
            }

            if ($password === null || !filter_var($password, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/']])) {
                throw new \Exception('Invalid password');
            }

            if ($username === null || !filter_var($username, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '/^[a-zA-Z0-9_]{3,25}$/']])) {
                throw new \Exception('Invalid username');
            }

            $user->setEmail($email);
            $hashedPassword = $passwordHasher->hashPassword(
                $user,
                $password
            );
            $user->setPassword($hashedPassword);
            $user->setUsername($username);
            $em->persist($user);
            $em->flush();

            return new JsonResponse(['message' => 'User created'], 201);
        } catch (\Exception $e) {
            return new JsonResponse(['message' => $e->getMessage()], 400);
        }

    }


}
