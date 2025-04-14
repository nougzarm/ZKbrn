use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use lox_zkp::{toolbox::{prover::Prover, verifier::Verifier, SchnorrCS}, Transcript};
use rand_core::OsRng; 

#[allow(nonstandard_style)]
fn main() {
    println!("Faisons une preuve via la librairie ZKP de tor");

    /* Aléa servant à génerer la paire de clés */
    let mut rng = OsRng;

    /* Générations des clées (privée/publique) */
    let x = Scalar::random(&mut rng);
    let P = x*G;

    /* Debug */
    println!("Clé privée aléatoire générée : x = {:?}", x);
    // println!("Clé publique : P = x*G = {:?}", P);

/*  |----------------------------------------------------------------------------------------------------------------|
    |   Côté prouveur                                                                                                |
    |----------------------------------------------------------------------------------------------------------------|
*/
    let mut transcript_pr = Transcript::new(b"PreuveExemple");
    let mut prouveur = Prover::new(b"preuveZK", &mut transcript_pr);
    /* Ajout des paramètres */
    let x_var = prouveur.allocate_scalar(b"x", x);  // Ajout de la clé pv
    let (P_var, _) = prouveur.allocate_point(b"P", P);  // Ajout de la clé pub
    let (G_var, _) = prouveur.allocate_point(b"G", G); // Ajout du point générateur

    prouveur.constrain(P_var, vec![(x_var, G_var)]); // Ajout de la contrainte P = x*G

    let preuve = prouveur.prove_compact();  // Création de la preuve

    /* Affichage de la preuve */
    println!("Challenge: {:?}", preuve.challenge);
    println!("Réponse: {:?}", preuve.responses);

/*  |----------------------------------------------------------------------------------------------------------------|
    |   Côté vérifieur                                                                                               |
    |----------------------------------------------------------------------------------------------------------------|
*/
    let mut transcript_vf = Transcript::new(b"PreuveExemple");
    let mut verifieur = Verifier::new(b"preuveZK", &mut transcript_vf);

    let x_var_vf = verifieur.allocate_scalar(b"x");
    let P_var_vf = verifieur.allocate_point(b"P", P.compress()).unwrap();
    let G_var_vf = verifieur.allocate_point(b"G", G.compress()).unwrap();

    verifieur.constrain(P_var_vf, vec![(x_var_vf, G_var_vf)]);

    match verifieur.verify_compact(&preuve) {
        Ok(()) => println!("La preuve est valide"),
        Err(_r) => println!("La preuve n'est pas valide"),
    }
}
