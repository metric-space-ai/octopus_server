import React from 'react';
import betathonLogo from './betathonLogo.png';
import './Main.css';

const MainPage = () => {
  return (
    <div>
      <main>
        <img
          alt='betathon logo'
          src={betathonLogo}
          className=' mb-16 shadow-lg border-2 rounded-md border-yellow-500/25'
          width={600}
          height={600}
        />

      </main>
    </div>
  );
};
export default MainPage;
